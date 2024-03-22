package sequencesender

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0xPolygonHermez/zkevm-data-streamer/datastreamer"
	"github.com/0xPolygonHermez/zkevm-ethtx-manager/ethtxmanager"
	ethtxlog "github.com/0xPolygonHermez/zkevm-ethtx-manager/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman"
	ethmanTypes "github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/state"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var (
	// ErrOversizedData when transaction input data is greater than a limit (DOS protection)
	ErrOversizedData = errors.New("oversized data")
)

const (
	// BLOB_TX_TYPE is a blob transaction type
	BLOB_TX_TYPE = byte(0x03)
)

// SequenceSender represents a sequence sender
type SequenceSender struct {
	cfg                 Config
	ethTxManager        *ethtxmanager.Client
	etherman            ethermaner
	currentNonce        uint64
	latestVirtualBatch  uint64                     // Latest virtualized batch obtained from L1
	latestVirtualTime   time.Time                  // Latest virtual batch timestamp
	latestSentToL1Batch uint64                     // Latest batch sent to L1
	wipBatch            uint64                     // Work in progress batch
	sequenceList        []uint64                   // Sequence of batch number to be send to L1
	sequenceData        map[uint64]*sequenceData   // All the batch data indexed by batch number
	mutexSequence       sync.Mutex                 // Mutex to access sequenceData and sequenceList
	ethTransactions     map[common.Hash]*ethTxData // All the eth tx sent to L1 indexed by hash
	ethTxData           map[common.Hash][]byte     // Tx data send to or received from L1
	mutexEthTx          sync.Mutex                 // Mutex to access ethTransactions
	sequencesTxFile     *os.File                   // Persistence of sent transactions
	validStream         bool                       // Not valid while receiving data before the desired batch
	fromStreamBatch     uint64                     // Initial batch to connect to the streaming
	latestStreamBatch   uint64                     // Latest batch received by the streaming
	seqSendingStopped   bool                       // If there is a critical error
	streamClient        *datastreamer.StreamClient
}

type sequenceData struct {
	batchClosed bool
	batch       *ethmanTypes.Sequence
	batchRaw    *state.BatchRawV2
}

type ethTxData struct {
	Nonce           uint64                              `json:"nonce"`
	Status          string                              `json:"status"`
	SentL1Timestamp time.Time                           `json:"sentL1Timestamp"`
	StatusTimestamp time.Time                           `json:"statusTimestamp"`
	FromBatch       uint64                              `json:"fromBatch"`
	ToBatch         uint64                              `json:"toBatch"`
	MinedAtBlock    big.Int                             `json:"minedAtBlock"`
	OnMonitor       bool                                `json:"onMonitor"`
	To              common.Address                      `json:"to"`
	StateHistory    []string                            `json:"stateHistory"`
	Txs             map[common.Hash]ethTxAdditionalData `json:"txs"`
}

type ethTxAdditionalData struct {
	GasPrice      *big.Int `json:"gasPrice,omitempty"`
	RevertMessage string   `json:"revertMessage,omitempty"`
}

// New inits sequence sender
func New(cfg Config, etherman ethermaner) (*SequenceSender, error) {
	// Create sequencesender
	s := SequenceSender{
		cfg:               cfg,
		etherman:          etherman,
		ethTransactions:   make(map[common.Hash]*ethTxData),
		ethTxData:         make(map[common.Hash][]byte),
		sequenceData:      make(map[uint64]*sequenceData),
		validStream:       false,
		latestStreamBatch: 0,
		seqSendingStopped: false,
	}

	// Restore pending sent sequences
	err := s.loadSentSequencesTransactions()
	if err != nil {
		log.Fatalf("[SeqSender] error restoring sent sequences from file", err)
		return nil, err
	}

	// Create ethtxmanager client
	cfg.EthTxManager.Log = ethtxlog.Config{
		Environment: ethtxlog.LogEnvironment(cfg.Log.Environment),
		Level:       cfg.Log.Level,
		Outputs:     cfg.Log.Outputs,
	}
	s.ethTxManager, err = ethtxmanager.New(cfg.EthTxManager)
	if err != nil {
		log.Fatalf("[SeqSender] error creating ethtxmanager client: %v", err)
		return nil, err
	}

	// Create datastream client
	s.streamClient, err = datastreamer.NewClient(s.cfg.StreamClient.Server, 1)
	if err != nil {
		log.Fatalf("[SeqSender] failed to create stream client, error: %v", err)
	} else {
		log.Infof("[SeqSender] new stream client")
	}
	// Set func to handle the streaming
	s.streamClient.SetProcessEntryFunc(s.handleReceivedDataStream)

	return &s, nil
}

// Start starts the sequence sender
func (s *SequenceSender) Start(ctx context.Context) {
	// Start ethtxmanager client
	go s.ethTxManager.Start()

	// Get current nonce
	var err error
	s.currentNonce, err = s.etherman.CurrentNonce(ctx, s.cfg.L2Coinbase)
	if err != nil {
		log.Fatalf("[SeqSender] failed to get current nonce from %v, error: %v", s.cfg.L2Coinbase, err)
	} else {
		log.Infof("[SeqSender] current nonce for %v is %d", s.cfg.L2Coinbase, s.currentNonce)
	}

	// Get latest virtual state batch from L1
	err = s.updateLatestVirtualBatch()
	if err != nil {
		log.Fatalf("[SeqSender] error getting latest sequenced batch, error: %v", err)
	}

	// Sync all monitored sent L1 tx
	err = s.syncAllEthTxResults(ctx)
	if err != nil {
		log.Fatalf("[SeqSender] failed to sync monitored tx results, error: %v", err)
	}

	// Start datastream client
	err = s.streamClient.Start()
	if err != nil {
		log.Fatalf("[SeqSender] failed to start stream client, error: %v", err)
	}

	// Set starting point of the streaming
	s.fromStreamBatch = s.latestVirtualBatch
	bookmark := []byte{state.BookMarkTypeBatch}
	bookmark = binary.BigEndian.AppendUint64(bookmark, s.fromStreamBatch)
	log.Infof("[SeqSender] stream client from bookmark %v", bookmark)

	// Current batch to sequence
	s.wipBatch = s.latestVirtualBatch + 1
	s.latestSentToL1Batch = s.latestVirtualBatch

	// Start sequence sending
	go s.sequenceSending(ctx)

	// Start receiving the streaming
	err = s.streamClient.ExecCommandStartBookmark(bookmark)
	if err != nil {
		log.Fatalf("[SeqSender] failed to connect to the streaming")
	}
}

// sequenceSending starts loop to check if there are sequences to send and sends them if it's convenient
func (s *SequenceSender) sequenceSending(ctx context.Context) {
	for {
		s.tryToSendSequence(ctx)
		time.Sleep(s.cfg.WaitPeriodSendSequence.Duration)
	}
}

// purgeSequences purges batches from memory structures
func (s *SequenceSender) purgeSequences() {
	// If sequence sending is stopped, do not purge
	if s.seqSendingStopped {
		return
	}

	// Purge the information of batches that are already virtualized
	s.mutexSequence.Lock()
	truncateUntil := 0
	toPurge := make([]uint64, 0)
	for i := 0; i < len(s.sequenceList); i++ {
		batchNumber := s.sequenceList[i]
		if batchNumber <= s.latestVirtualBatch {
			truncateUntil = i + 1
			toPurge = append(toPurge, batchNumber)
		}
	}

	if len(toPurge) > 0 {
		s.sequenceList = s.sequenceList[truncateUntil:]

		var firstPurged uint64
		var lastPurged uint64
		for i := 0; i < len(toPurge); i++ {
			if i == 0 {
				firstPurged = toPurge[i]
			}
			if i == len(toPurge)-1 {
				lastPurged = toPurge[i]
			}
			delete(s.sequenceData, toPurge[i])
		}
		log.Infof("[SeqSender] batches purged count: %d, fromBatch: %d, toBatch: %d", len(toPurge), firstPurged, lastPurged)
	}
	s.mutexSequence.Unlock()
}

// purgeEthTx purges transactions from memory structures
func (s *SequenceSender) purgeEthTx(ctx context.Context) {
	// If sequence sending is stopped, do not purge
	if s.seqSendingStopped {
		return
	}

	// Purge old transactions that are finalized
	s.mutexEthTx.Lock()
	timePurge := time.Now().Add(-s.cfg.WaitPeriodPurgeTxFile.Duration)
	toPurge := make([]common.Hash, 0)
	for hash, data := range s.ethTransactions {
		if !data.StatusTimestamp.Before(timePurge) {
			continue
		}

		if !data.OnMonitor || data.Status == ethtxmanager.MonitoredTxStatusFinalized.String() {
			toPurge = append(toPurge, hash)

			// Remove from tx monitor
			if data.OnMonitor {
				err := s.ethTxManager.Remove(ctx, hash)
				if err != nil {
					log.Warnf("[SeqSender] error removing monitor tx %v from ethtxmanager: %v", hash, err)
				} else {
					log.Infof("[SeqSender] removed monitor tx %v from ethtxmanager", hash)
				}
			}
		}
	}

	if len(toPurge) > 0 {
		var firstPurged uint64 = math.MaxUint64
		var lastPurged uint64
		for i := 0; i < len(toPurge); i++ {
			if s.ethTransactions[toPurge[i]].Nonce < firstPurged {
				firstPurged = s.ethTransactions[toPurge[i]].Nonce
			}
			if s.ethTransactions[toPurge[i]].Nonce > lastPurged {
				lastPurged = s.ethTransactions[toPurge[i]].Nonce
			}
			delete(s.ethTransactions, toPurge[i])
			delete(s.ethTxData, toPurge[i])
		}
		log.Infof("[SeqSender] txs purged count: %d, fromNonce: %d, toNonce: %d", len(toPurge), firstPurged, lastPurged)
	}
	s.mutexEthTx.Unlock()
}

// syncEthTxResults syncs results from L1 for transactions in the memory structure
func (s *SequenceSender) syncEthTxResults(ctx context.Context) (uint64, error) {
	s.mutexEthTx.Lock()
	var txPending uint64
	for hash, data := range s.ethTransactions {
		if data.Status == ethtxmanager.MonitoredTxStatusFinalized.String() {
			continue
		}

		_ = s.getResultAndUpdateEthTx(ctx, hash)
		txStatus := s.ethTransactions[hash].Status
		// Count if it is not in a final state
		if s.ethTransactions[hash].OnMonitor &&
			txStatus != ethtxmanager.MonitoredTxStatusFailed.String() &&
			txStatus != ethtxmanager.MonitoredTxStatusConsolidated.String() &&
			txStatus != ethtxmanager.MonitoredTxStatusFinalized.String() {
			txPending++
		}
	}
	s.mutexEthTx.Unlock()

	// Save updated sequences transactions
	err := s.saveSentSequencesTransactions(ctx)
	if err != nil {
		log.Errorf("[SeqSender] error saving tx sequence, error: %v", err)
	}

	return txPending, nil
}

// syncAllEthTxResults syncs all tx results from L1
func (s *SequenceSender) syncAllEthTxResults(ctx context.Context) error {
	// Get all results
	results, err := s.ethTxManager.ResultsByStatus(ctx, nil)
	if err != nil {
		log.Errorf("[SeqSender] error getting results for all tx: %v", err)
		return err
	}

	// Check and update tx status
	s.mutexEthTx.Lock()
	for _, result := range results {
		txSequence, exists := s.ethTransactions[result.ID]
		if !exists {
			log.Infof("[SeqSender] transaction %v missing in memory structure. Adding it", result.ID)
			// No info: from/to batch and the sent timestamp
			s.ethTransactions[result.ID] = &ethTxData{
				SentL1Timestamp: time.Time{},
				StatusTimestamp: time.Now(),
				OnMonitor:       true,
				Status:          "*missing",
			}
			txSequence = s.ethTransactions[result.ID]
		}

		s.updateEthTxResult(txSequence, result)
	}
	s.mutexEthTx.Unlock()

	// Save updated sequences transactions
	err = s.saveSentSequencesTransactions(ctx)
	if err != nil {
		log.Errorf("[SeqSender] error saving tx sequence, error: %v", err)
	}

	return nil
}

// copyTxData copies tx data in the internal structure
func (s *SequenceSender) copyTxData(txHash common.Hash, txData []byte, txsResults map[common.Hash]ethtxmanager.TxResult) {
	s.ethTxData[txHash] = make([]byte, len(txData))
	copy(s.ethTxData[txHash], txData)

	s.ethTransactions[txHash].Txs = make(map[common.Hash]ethTxAdditionalData, 0)
	for hash, result := range txsResults {
		var gasPrice *big.Int
		if result.Tx != nil {
			gasPrice = result.Tx.GasPrice()
		}

		add := ethTxAdditionalData{
			GasPrice:      gasPrice,
			RevertMessage: result.RevertMessage,
		}
		s.ethTransactions[txHash].Txs[hash] = add
	}
}

// updateEthTxResult handles updating transaction state
func (s *SequenceSender) updateEthTxResult(txData *ethTxData, txResult ethtxmanager.MonitoredTxResult) {
	if txData.Status != txResult.Status.String() {
		log.Infof("[SeqSender] update transaction %v to state %s", txResult.ID, txResult.Status.String())
		txData.StatusTimestamp = time.Now()
		stTrans := txData.StatusTimestamp.Format("2006-01-02T15:04:05.000-07:00") + ", " + txData.Status + ", " + txResult.Status.String()
		txData.Status = txResult.Status.String()
		txData.StateHistory = append(txData.StateHistory, stTrans)

		// Manage according to the state
		statusConsolidated := txData.Status == ethtxmanager.MonitoredTxStatusConsolidated.String() || txData.Status == ethtxmanager.MonitoredTxStatusFinalized.String()
		if txData.Status == ethtxmanager.MonitoredTxStatusFailed.String() {
			s.logFatalf("[SeqSender] transaction %v result failed!")
		} else if statusConsolidated && txData.ToBatch >= s.latestVirtualBatch {
			s.latestVirtualTime = txData.StatusTimestamp
		}
	}

	// Update info received from L1
	txData.Nonce = txResult.Nonce
	if txResult.To != nil {
		txData.To = *txResult.To
	}
	if txResult.MinedAtBlockNumber != nil {
		txData.MinedAtBlock = *txResult.MinedAtBlockNumber
	}
	s.copyTxData(txResult.ID, txResult.Data, txResult.Txs)
}

// getResultAndUpdateEthTx updates the tx status from the ethTxManager
func (s *SequenceSender) getResultAndUpdateEthTx(ctx context.Context, txHash common.Hash) error {
	txData, exists := s.ethTransactions[txHash]
	if !exists {
		log.Errorf("[SeqSender] transaction %v not found in memory", txHash)
		return errors.New("transaction not found in memory structure")
	}

	txResult, err := s.ethTxManager.Result(ctx, txHash)
	if err == ethtxmanager.ErrNotFound {
		log.Infof("[SeqSender] transaction %v does not exist in ethtxmanager. Marking it", txHash)
		txData.OnMonitor = false
		// Resend tx?
		// _ = s.sendTx(ctx, true, &txHash, nil, 0, 0, nil)
	} else if err != nil {
		log.Errorf("[SeqSender] error getting result for tx %v: %v", txHash, err)
		return err
	} else {
		s.updateEthTxResult(txData, txResult)
	}

	return nil
}

// tryToSendSequence checks if there is a sequence and it's worth it to send to L1
func (s *SequenceSender) tryToSendSequence(ctx context.Context) {
	// Update latest virtual batch
	log.Infof("[SeqSender] updating virtual batch")
	err := s.updateLatestVirtualBatch()
	if err != nil {
		return
	}

	// Update state of transactions
	log.Infof("[SeqSender] updating tx results")
	countPending, err := s.syncEthTxResults(ctx)
	if err != nil {
		return
	}

	// Check if the sequence sending is stopped
	if s.seqSendingStopped {
		log.Warnf("[SeqSender] sending is stopped!")
		return
	}

	// Check if reached the maximum number of pending transactions
	if countPending >= s.cfg.MaxPendingTx {
		log.Infof("[SeqSender] max number of pending txs (%d) reached. Waiting for some to be completed", countPending)
		return
	}

	// Check if should send sequence to L1
	log.Infof("[SeqSender] getting sequences to send")
	sequences, useBlobs, err := s.getSequencesToSend()
	if err != nil || len(sequences) == 0 {
		if err != nil {
			log.Errorf("[SeqSender] error getting sequences: %v", err)
		}
		return
	}

	// Send sequences to L1
	sequenceCount := len(sequences)
	firstSequence := sequences[0]
	lastSequence := sequences[sequenceCount-1]
	log.Infof("[SeqSender] sending sequences to L1 (using BLOB? %t): from batch %d to %d", useBlobs, firstSequence.BatchNumber, lastSequence.BatchNumber)
	printSequences(sequences)

	// Build sequence data
	var to *common.Address
	var data []byte
	var sidecar *types.BlobTxSidecar
	if !useBlobs {
		to, data, err = s.etherman.BuildSequenceBatchesTxData(s.cfg.SenderAddress, sequences, uint64(lastSequence.LastL2BLockTimestamp), firstSequence.BatchNumber-1, s.cfg.L2Coinbase)
		if err != nil {
			log.Errorf("[SeqSender] error estimating new sequenceBatches as CallData to add to ethtxmanager: ", err)
			return
		}
	} else {
		to, data, sidecar, err = s.etherman.BuildSequenceBatchesTxBlob(s.cfg.SenderAddress, sequences, uint64(lastSequence.LastL2BLockTimestamp), firstSequence.BatchNumber-1, s.cfg.L2Coinbase)
		if err != nil {
			log.Errorf("[SeqSender] error estimating new sequenceBatches as Blobs to add to ethtxmanager: ", err)
			return
		}
	}

	// Add sequence tx
	err = s.sendTx(ctx, false, nil, to, firstSequence.BatchNumber, lastSequence.BatchNumber, data, sidecar)
	if err != nil {
		return
	}

	// Purge sequences data from memory
	s.purgeSequences()
}

// sendTx adds transaction to the ethTxManager to send it to L1
func (s *SequenceSender) sendTx(ctx context.Context, resend bool, txOldHash *common.Hash, to *common.Address, fromBatch uint64, toBatch uint64, data []byte, sidecar *types.BlobTxSidecar) error {
	// Params if new tx to send or resend a previous tx
	var paramTo *common.Address
	var paramNonce *uint64
	var paramData []byte
	var valueFromBatch uint64
	var valueToBatch uint64
	var valueToAddress common.Address

	if !resend {
		paramTo = to
		paramNonce = &s.currentNonce
		paramData = data
		valueFromBatch = fromBatch
		valueToBatch = toBatch
	} else {
		if txOldHash == nil {
			log.Errorf("[SeqSender] trying to resend a tx with nil hash")
			return errors.New("resend tx with nil hash monitor id")
		}
		paramTo = &s.ethTransactions[*txOldHash].To
		paramNonce = &s.ethTransactions[*txOldHash].Nonce
		paramData = s.ethTxData[*txOldHash]
		valueFromBatch = s.ethTransactions[*txOldHash].FromBatch
		valueToBatch = s.ethTransactions[*txOldHash].ToBatch
	}
	if paramTo != nil {
		valueToAddress = *paramTo
	}

	// Add sequence tx
	txHash, err := s.ethTxManager.Add(ctx, paramTo, paramNonce, big.NewInt(0), paramData, sidecar)
	if err != nil {
		log.Errorf("[SeqSender] error adding sequence to ethtxmanager: %v", err)
		return err
	}
	if !resend {
		s.currentNonce++
	}

	// Add new eth tx
	txData := ethTxData{
		SentL1Timestamp: time.Now(),
		StatusTimestamp: time.Now(),
		Status:          "*new",
		FromBatch:       valueFromBatch,
		ToBatch:         valueToBatch,
		OnMonitor:       true,
		To:              valueToAddress,
	}

	// Add tx to internal structure
	s.mutexEthTx.Lock()
	s.ethTransactions[txHash] = &txData
	txResults := make(map[common.Hash]ethtxmanager.TxResult, 0)
	s.copyTxData(txHash, paramData, txResults)
	_ = s.getResultAndUpdateEthTx(ctx, txHash)
	if !resend {
		s.latestSentToL1Batch = valueToBatch
	} else {
		s.ethTransactions[*txOldHash].Status = "*resent"
	}
	s.mutexEthTx.Unlock()

	// Save sent sequences
	err = s.saveSentSequencesTransactions(ctx)
	if err != nil {
		log.Errorf("[SeqSender] error saving tx sequence sent, error: %v", err)
	}
	return nil
}

// getSequencesToSend generates sequences to be sent to L1. Empty array means there are no sequences to send or it's not worth sending
func (s *SequenceSender) getSequencesToSend() ([]ethmanTypes.Sequence, bool, error) {
	// Add sequences until too big for a single L1 tx or last batch is reached
	s.mutexSequence.Lock()
	defer s.mutexSequence.Unlock()
	useBlobs := false
	sequences := []ethmanTypes.Sequence{}
	for i := 0; i < len(s.sequenceList); i++ {
		batchNumber := s.sequenceList[i]
		if batchNumber <= s.latestVirtualBatch || batchNumber <= s.latestSentToL1Batch {
			continue
		}

		// Check if the next batch belongs to a new forkid, in this case we need to stop sequencing as we need to
		// wait the upgrade of forkid is completed and s.cfg.NumBatchForkIdUpgrade is disabled (=0) again
		if (s.cfg.ForkUpgradeBatchNumber != 0) && (batchNumber == (s.cfg.ForkUpgradeBatchNumber + 1)) {
			return nil, false, fmt.Errorf("aborting sequencing process as we reached the batch %d where a new forkid is applied (upgrade)", s.cfg.ForkUpgradeBatchNumber+1)
		}

		// Check if batch is closed
		if !s.sequenceData[batchNumber].batchClosed {
			// Reached current wip batch
			break
		}

		// Add new sequence
		batch := *s.sequenceData[batchNumber].batch
		sequences = append(sequences, batch)
		firstSequence := sequences[0]
		lastSequence := sequences[len(sequences)-1]

		// Check if can be send
		tx, err := s.etherman.EstimateGasSequenceBatches(s.cfg.SenderAddress, sequences, uint64(lastSequence.LastL2BLockTimestamp), firstSequence.BatchNumber-1, s.cfg.L2Coinbase)
		if err == nil {
			useBlobs = tx.Type() == BLOB_TX_TYPE

			if !useBlobs && tx.Size() > s.cfg.MaxTxSizeForL1 {
				log.Infof("[SeqSender] oversized Data on TX oldHash %s (txSize %d > %d)", tx.Hash(), tx.Size(), s.cfg.MaxTxSizeForL1)
				err = ErrOversizedData
			}
		}

		if err != nil {
			log.Infof("[SeqSender] handling estimate gas send sequence error: %v", err)
			sequences, err = s.handleEstimateGasSendSequenceErr(sequences, batchNumber, err)
			if sequences != nil {
				if len(sequences) > 0 {
					// Handling the error gracefully, re-processing the sequence as a sanity check
					lastSequence = sequences[len(sequences)-1]
					tx, err = s.etherman.EstimateGasSequenceBatches(s.cfg.SenderAddress, sequences, uint64(lastSequence.LastL2BLockTimestamp), firstSequence.BatchNumber-1, s.cfg.L2Coinbase)
					if err == nil {
						useBlobs = tx.Type() == BLOB_TX_TYPE
					}
					return sequences, useBlobs, err
				}
			}
			return sequences, useBlobs, err
		}

		// Check if the current batch is the last before a change to a new forkid, in this case we need to close and send the sequence to L1
		if (s.cfg.ForkUpgradeBatchNumber != 0) && (batchNumber == (s.cfg.ForkUpgradeBatchNumber)) {
			log.Infof("[SeqSender] sequence should be sent to L1, as we have reached the batch %d from which a new forkid is applied (upgrade)", s.cfg.ForkUpgradeBatchNumber)
			return sequences, useBlobs, nil
		}
	}

	// Reached latest batch. Decide if it's worth to send the sequence, or wait for new batches
	if len(sequences) == 0 {
		log.Infof("[SeqSender] no batches to be sequenced")
		return nil, false, nil
	}

	if s.latestVirtualTime.Before(time.Now().Add(-s.cfg.LastBatchVirtualizationTimeMaxWaitPeriod.Duration)) {
		log.Infof("[SeqSender] sequence should be sent, too much time without sending anything to L1")
		return sequences, useBlobs, nil
	}

	log.Infof("[SeqSender] not enough time has passed since last batch was virtualized and the sequence could be bigger")
	return nil, false, nil
}

// handleEstimateGasSendSequenceErr handles an error on the estimate gas. Results: (nil,nil)=requires waiting, (nil,error)=no handled gracefully, (seq,nil) handled gracefully
func (s *SequenceSender) handleEstimateGasSendSequenceErr(sequences []ethmanTypes.Sequence, currentBatchNumToSequence uint64, err error) ([]ethmanTypes.Sequence, error) {
	// Insufficient allowance
	if errors.Is(err, etherman.ErrInsufficientAllowance) {
		return nil, err
	}
	if isDataForEthTxTooBig(err) {
		// Remove the latest item and send the sequences
		log.Infof(
			"Done building sequences, selected batches to %d. Batch %d caused the L1 tx to be too big",
			currentBatchNumToSequence-1, currentBatchNumToSequence,
		)
		sequences = sequences[:len(sequences)-1]
		return sequences, nil
	}

	// Remove the latest item and send the sequences
	log.Infof(
		"Done building sequences, selected batches to %d. Batch %d excluded due to unknown error: %v",
		currentBatchNumToSequence, currentBatchNumToSequence+1, err,
	)
	sequences = sequences[:len(sequences)-1]

	return sequences, nil
}

// isDataForEthTxTooBig checks if tx oversize error
func isDataForEthTxTooBig(err error) bool {
	return errors.Is(err, etherman.ErrGasRequiredExceedsAllowance) ||
		errors.Is(err, ErrOversizedData) ||
		errors.Is(err, etherman.ErrContentLengthTooLarge) ||
		errors.Is(err, etherman.ErrBlobOversizedData)
}

// loadSentSequencesTransactions loads the file into the memory structure
func (s *SequenceSender) loadSentSequencesTransactions() error {
	// Check if file exists
	if _, err := os.Stat(s.cfg.SequencesTxFileName); os.IsNotExist(err) {
		log.Infof("[SeqSender] file not found %s: %v", s.cfg.SequencesTxFileName, err)
		return nil
	} else if err != nil {
		log.Errorf("[SeqSender] error opening file %s: %v", s.cfg.SequencesTxFileName, err)
		return err
	}

	// Read file
	data, err := os.ReadFile(s.cfg.SequencesTxFileName)
	if err != nil {
		log.Errorf("[SeqSender] error reading file %s: %v", s.cfg.SequencesTxFileName, err)
		return err
	}

	// Restore memory structure
	s.mutexEthTx.Lock()
	err = json.Unmarshal(data, &s.ethTransactions)
	s.mutexEthTx.Unlock()
	if err != nil {
		log.Errorf("[SeqSender] error decoding data from %s: %v", s.cfg.SequencesTxFileName, err)
		return err
	}

	return nil
}

// saveSentSequencesTransactions saves memory structure into persistent file
func (s *SequenceSender) saveSentSequencesTransactions(ctx context.Context) error {
	var err error

	// Purge tx
	s.purgeEthTx(ctx)

	// Ceate file
	fileName := s.cfg.SequencesTxFileName[0:strings.IndexRune(s.cfg.SequencesTxFileName, '.')] + ".tmp"
	s.sequencesTxFile, err = os.Create(fileName)
	if err != nil {
		log.Errorf("[SeqSender] error creating file %s: %v", fileName, err)
		return err
	}
	defer s.sequencesTxFile.Close()

	// Write data JSON encoded
	encoder := json.NewEncoder(s.sequencesTxFile)
	encoder.SetIndent("", "  ")
	s.mutexEthTx.Lock()
	err = encoder.Encode(s.ethTransactions)
	s.mutexEthTx.Unlock()
	if err != nil {
		log.Errorf("[SeqSender] error writing file %s: %v", fileName, err)
		return err
	}

	// Rename the new file
	err = os.Rename(fileName, s.cfg.SequencesTxFileName)
	if err != nil {
		log.Errorf("[SeqSender] error renaming file %s to %s: %v", fileName, s.cfg.SequencesTxFileName, err)
		return err
	}

	return nil
}

// handleReceivedDataStream manages the events received by the streaming
func (s *SequenceSender) handleReceivedDataStream(e *datastreamer.FileEntry, c *datastreamer.StreamClient, ss *datastreamer.StreamServer) error {
	switch e.Type {
	case state.EntryTypeL2BlockStart:
		// Handle stream entry: Start L2 Block
		l2BlockStart := state.DSL2BlockStart{}.Decode(e.Data)

		// Already virtualized
		if l2BlockStart.BatchNumber <= s.fromStreamBatch {
			if l2BlockStart.BatchNumber != s.latestStreamBatch {
				log.Infof("[SeqSender] skipped! batch already virtualized, number %d", l2BlockStart.BatchNumber)
			}
		} else if !s.validStream && l2BlockStart.BatchNumber == s.fromStreamBatch+1 {
			// Initial case after startup
			s.addNewSequenceBatch(l2BlockStart)
			s.validStream = true
		}

		// Latest stream batch
		s.latestStreamBatch = l2BlockStart.BatchNumber
		if !s.validStream {
			return nil
		}

		// Handle whether it's only a new block or also a new batch
		if l2BlockStart.BatchNumber > s.wipBatch {
			// New batch in the sequence
			// Close current batch
			err := s.closeSequenceBatch()
			if err != nil {
				log.Fatalf("[SeqSender] error closing wip batch")
				return err
			}

			// Create new sequential batch
			s.addNewSequenceBatch(l2BlockStart)
		}

		// Add L2 block
		s.addNewBatchL2Block(l2BlockStart)

	case state.EntryTypeL2Tx:
		// Handle stream entry: L2 Tx
		if !s.validStream {
			return nil
		}

		l2Tx := state.DSL2Transaction{}
		l2Tx = l2Tx.Decode(e.Data)

		// Add tx data
		s.addNewBlockTx(l2Tx)

	case state.EntryTypeL2BlockEnd:
		// Handle stream entry: End L2 Block
		l2BlockEnd := state.DSL2BlockEnd{}.Decode(e.Data)

		if !s.validStream {
			return nil
		}

		// Add end block data
		s.addInfoSequenceBatch(l2BlockEnd)
	}
	return nil
}

// closeSequenceBatch closes the current batch
func (s *SequenceSender) closeSequenceBatch() error {
	s.mutexSequence.Lock()
	log.Infof("[SeqSender] closing batch %d", s.wipBatch)

	data := s.sequenceData[s.wipBatch]
	if data != nil {
		data.batchClosed = true

		var err error
		data.batch.BatchL2Data, err = state.EncodeBatchV2(data.batchRaw)
		if err != nil {
			log.Errorf("[SeqSender] error closing and encoding the batch %d: %v", s.wipBatch, err)
			return err
		}
	}

	s.mutexSequence.Unlock()
	return nil
}

// addNewSequenceBatch adds a new batch to the sequence
func (s *SequenceSender) addNewSequenceBatch(l2BlockStart state.DSL2BlockStart) {
	s.mutexSequence.Lock()
	log.Infof("[SeqSender] ...new batch, number %d", l2BlockStart.BatchNumber)

	if l2BlockStart.BatchNumber > s.wipBatch+1 {
		s.logFatalf("[SeqSender] new batch number (%d) is not consecutive to the current one (%d)", l2BlockStart.BatchNumber, s.wipBatch)
	} else if l2BlockStart.BatchNumber < s.wipBatch {
		s.logFatalf("[SeqSender] new batch number (%d) is lower than the current one (%d)", l2BlockStart.BatchNumber, s.wipBatch)
	}

	// Create sequence
	sequence := ethmanTypes.Sequence{
		GlobalExitRoot:       l2BlockStart.GlobalExitRoot,
		LastL2BLockTimestamp: l2BlockStart.Timestamp,
		BatchNumber:          l2BlockStart.BatchNumber,
	}

	// Add to the list
	s.sequenceList = append(s.sequenceList, l2BlockStart.BatchNumber)

	// Create initial data
	batchRaw := state.BatchRawV2{}
	data := sequenceData{
		batchClosed: false,
		batch:       &sequence,
		batchRaw:    &batchRaw,
	}
	s.sequenceData[l2BlockStart.BatchNumber] = &data

	// Update wip batch
	s.wipBatch = l2BlockStart.BatchNumber
	s.mutexSequence.Unlock()
}

// addInfoSequenceBatch adds info from the block end data
func (s *SequenceSender) addInfoSequenceBatch(l2BlockEnd state.DSL2BlockEnd) {
	s.mutexSequence.Lock()

	// Current batch
	data := s.sequenceData[s.wipBatch]
	if data != nil {
		wipBatch := data.batch
		wipBatch.StateRoot = l2BlockEnd.StateRoot
	}

	s.mutexSequence.Unlock()
}

// addNewBatchL2Block adds a new L2 block to the work in progress batch
func (s *SequenceSender) addNewBatchL2Block(l2BlockStart state.DSL2BlockStart) {
	s.mutexSequence.Lock()
	log.Infof("[SeqSender] .....new L2 block, number %d (batch %d)", l2BlockStart.L2BlockNumber, l2BlockStart.BatchNumber)

	// Current batch
	data := s.sequenceData[s.wipBatch]
	if data != nil {
		wipBatchRaw := data.batchRaw
		data.batch.LastL2BLockTimestamp = l2BlockStart.Timestamp

		// New L2 block raw
		newBlockRaw := state.L2BlockRaw{}

		// Add L2 block
		wipBatchRaw.Blocks = append(wipBatchRaw.Blocks, newBlockRaw)

		// Get current L2 block
		_, blockRaw := s.getWipL2Block()
		if blockRaw == nil {
			log.Debugf("[SeqSender] wip block %d not found!")
			return
		}

		// Fill in data
		blockRaw.DeltaTimestamp = l2BlockStart.DeltaTimestamp
		blockRaw.IndexL1InfoTree = l2BlockStart.L1InfoTreeIndex
	}

	s.mutexSequence.Unlock()
}

// addNewBlockTx adds a new Tx to the current L2 block
func (s *SequenceSender) addNewBlockTx(l2Tx state.DSL2Transaction) {
	s.mutexSequence.Lock()
	log.Debugf("[SeqSender] ........new tx, length %d EGP %d SR %x..", l2Tx.EncodedLength, l2Tx.EffectiveGasPricePercentage, l2Tx.StateRoot[:8])

	// Current L2 block
	_, blockRaw := s.getWipL2Block()

	// New Tx raw
	tx, err := state.DecodeTx(common.Bytes2Hex(l2Tx.Encoded))
	if err != nil {
		log.Fatalf("[SeqSender] error decoding tx!")
		return
	}

	l2TxRaw := state.L2TxRaw{
		EfficiencyPercentage: l2Tx.EffectiveGasPricePercentage,
		TxAlreadyEncoded:     false,
		Tx:                   *tx,
	}

	// Add Tx
	blockRaw.Transactions = append(blockRaw.Transactions, l2TxRaw)
	s.mutexSequence.Unlock()
}

// getWipL2Block returns index of the array and pointer to the current L2 block (helper func)
func (s *SequenceSender) getWipL2Block() (uint64, *state.L2BlockRaw) {
	// Current batch
	var wipBatchRaw *state.BatchRawV2
	if s.sequenceData[s.wipBatch] != nil {
		wipBatchRaw = s.sequenceData[s.wipBatch].batchRaw
	}

	// Current wip block
	if len(wipBatchRaw.Blocks) > 0 {
		blockIndex := uint64(len(wipBatchRaw.Blocks)) - 1
		return blockIndex, &wipBatchRaw.Blocks[blockIndex]
	} else {
		return 0, nil
	}
}

// updateLatestVirtualBatch queries the value in L1 and updates the latest virtual batch field
func (s *SequenceSender) updateLatestVirtualBatch() error {
	// Get latest virtual state batch from L1
	var err error

	s.latestVirtualBatch, err = s.etherman.GetLatestBatchNumber()
	if err != nil {
		log.Errorf("[SeqSender] error getting latest virtual batch, error: %v", err)
		return errors.New("fail to get latest virtual batch")
	} else {
		log.Infof("[SeqSender] latest virtual batch is %d", s.latestVirtualBatch)
	}
	return nil
}

// logFatalf logs error, activates flag to stop sequencing, and remains in an infinite loop
func (s *SequenceSender) logFatalf(template string, args ...interface{}) {
	s.seqSendingStopped = true
	log.Errorf(template, args...)
	log.Errorf("[SeqSender] sequence sending stopped.")
	for {
		time.Sleep(1 * time.Second)
	}
}

// printSequences prints data from slice of type sequences
func printSequences(sequences []ethmanTypes.Sequence) {
	for i, seq := range sequences {
		log.Debugf("[SeqSender] // sequence(%d): batch: %d, ts: %v, lenData: %d, GER: %x..", i, seq.BatchNumber, seq.LastL2BLockTimestamp, len(seq.BatchL2Data), seq.GlobalExitRoot[:8])
	}
}

// printBatch prints data from batch raw V2
func printBatch(raw *state.BatchRawV2, showBlock bool, showTx bool) {
	// Total amount of L2 tx in the batch
	totalL2Txs := 0
	for k := 0; k < len(raw.Blocks); k++ {
		totalL2Txs += len(raw.Blocks[k].Transactions)
	}

	log.Debugf("[SeqSender] // #blocks: %d, #L2txs: %d", len(raw.Blocks), totalL2Txs)

	// Blocks info
	if showBlock {
		numBlocks := len(raw.Blocks)
		var firstBlock *state.L2BlockRaw
		var lastBlock *state.L2BlockRaw
		if numBlocks > 0 {
			firstBlock = &raw.Blocks[0]
		}
		if numBlocks > 1 {
			lastBlock = &raw.Blocks[numBlocks-1]
		}
		if firstBlock != nil {
			log.Debugf("[SeqSender] //    block first (indL1info: %d, delta-timestamp: %d, #L2txs: %d)", firstBlock.IndexL1InfoTree, firstBlock.DeltaTimestamp, len(firstBlock.Transactions))
			// Tx info
			if showTx {
				for iTx, tx := range firstBlock.Transactions {
					v, r, s := tx.Tx.RawSignatureValues()
					log.Debugf("[SeqSender] //       tx(%d) effPct: %d, encoded: %t, v: %v, r: %v, s: %v", iTx, tx.EfficiencyPercentage, tx.TxAlreadyEncoded, v, r, s)
				}
			}
		}
		if lastBlock != nil {
			log.Debugf("[SeqSender] //    block last (indL1info: %d, delta-timestamp: %d, #L2txs: %d)", lastBlock.DeltaTimestamp, lastBlock.DeltaTimestamp, len(lastBlock.Transactions))
		}
	}
}
