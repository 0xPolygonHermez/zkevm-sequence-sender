package sequencesender

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0xPolygonHermez/zkevm-data-streamer/datastreamer"
	"github.com/0xPolygonHermez/zkevm-ethtx-manager/ethtxmanager"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/state"
	"github.com/ethereum/go-ethereum/common"
)

var (
	// ErrOversizedData is returned if the input data of a transaction is greater
	// than some meaningful limit a user might use. This is not a consensus error
	// making the transaction invalid, rather a DOS protection.
	ErrOversizedData = errors.New("oversized data")
)

// SequenceSender represents a sequence sender
type SequenceSender struct {
	cfg                 Config
	ethTxManager        *ethtxmanager.Client
	etherman            *etherman.Client
	latestVirtualBatch  uint64                    // Latest virtualized batch obtained from L1
	latestSentToL1Batch uint64                    // Latest batch sent to L1
	wipBatch            uint64                    // Work in progress batch
	sequenceList        []uint64                  // Sequence of batch number to be send to L1
	sequenceData        map[uint64]*sequenceData  // All the batch data indexed by batch number
	mutexSequence       sync.Mutex                // Mutex to update sequence data
	ethTransactions     map[common.Hash]ethTxData // All the eth tx sent to L1 indexed by hash
	sequencesTxFile     *os.File
	validStream         bool   // Not valid while receiving data before the desired batch
	fromStreamBatch     uint64 // Initial batch to connect to the streaming
	latestStreamBatch   uint64 // Latest batch received by the streaming
	streamClient        *datastreamer.StreamClient
	prevBlockHash       common.Hash
}

type sequenceData struct {
	batchClosed bool
	batch       *types.Sequence
	batchRaw    *state.BatchRawV2
}

type ethTxData struct {
	Status    string `json:"status"`
	FromBatch uint64 `json:"fromBatch"`
	ToBatch   uint64 `json:"toBatch"`
}

// New inits sequence sender
func New(cfg Config, etherman *etherman.Client) (*SequenceSender, error) {
	log.Infof("CONFIG: %+v", cfg)

	// Create sequencesender
	s := SequenceSender{
		cfg:               cfg,
		etherman:          etherman,
		ethTransactions:   make(map[common.Hash]ethTxData),
		sequenceData:      make(map[uint64]*sequenceData),
		validStream:       false,
		latestStreamBatch: 0,
	}

	// Restore pending sent sequences
	err := s.loadSentSequencesTransactions()
	if err != nil {
		log.Fatalf("[SeqSender] error restoring sent sequences from file", err)
		return nil, err
	}
	s.printSequences(0, true, true)

	// Create ethtxmanager client
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
		log.Debugf("[SeqSender] new stream client")
	}
	// Set func to handle the streaming
	s.streamClient.SetProcessEntryFunc(s.handleReceivedDataStream)

	return &s, nil
}

// Start starts the sequence sender
func (s *SequenceSender) Start(ctx context.Context) {
	// Start ethtxmanager client
	go s.ethTxManager.Start()

	// Sync all monitored sent L1 tx
	err := s.syncAllEthTxResults(ctx)
	if err != nil {
		log.Fatalf("[SeqSender] failed to sync monitored tx results, error: %v", err)
	}

	// Start datastream client
	err = s.streamClient.Start()
	if err != nil {
		log.Fatalf("[SeqSender] failed to start stream client, error: %v", err)
	}

	// Get latest virtual state batch from L1
	err = s.updateLatestVirtualBatch()
	if err != nil {
		log.Fatalf("[SeqSender] error getting latest sequenced batch, error: %v", err)
	}

	// Set starting point of the streaming
	s.fromStreamBatch = s.latestVirtualBatch
	bookmark := []byte{state.BookMarkTypeBatch}
	bookmark = binary.BigEndian.AppendUint64(bookmark, s.fromStreamBatch)
	s.streamClient.FromBookmark = bookmark
	log.Debugf("[SeqSender] stream client from bookmark %v", bookmark)

	// Current batch to sequence
	s.wipBatch = s.latestVirtualBatch + 1
	s.latestSentToL1Batch = s.latestVirtualBatch

	// Start receiving the streaming
	err = s.streamClient.ExecCommand(datastreamer.CmdStart)
	if err != nil {
		log.Fatalf("[SeqSender] failed to connect to the streaming")
	}

	// Start sending sequences
	ticker := time.NewTicker(s.cfg.WaitPeriodSendSequence.Duration)
	for {
		s.tryToSendSequence(ctx, ticker)
	}
}

func (s *SequenceSender) updateEthTxResults(ctx context.Context) error {
	for hash, data := range s.ethTransactions {
		txResult, err := s.ethTxManager.Result(ctx, hash)
		if err == ethtxmanager.ErrNotFound {
			log.Debugf("[SeqSender] transaction %v does not exist in ethtxmanager. Removing it", hash)
			// delete(s.ethTransactions, hash)
			data.Status = "notexists"
		} else if err != nil {
			log.Errorf("[SeqSender] Error getting result for tx %v: %v", hash, err)
		} else {
			// Update tx status
			log.Debugf("[SeqSender] transaction %v status %s", hash, string(txResult.Status))
			data.Status = string(txResult.Status)
		}

		// TODO: Manage according to the state
	}

	s.printEthTxs()
	return nil
}

func (s *SequenceSender) syncAllEthTxResults(ctx context.Context) error {
	// Get all results
	results, err := s.ethTxManager.ResultsByStatus(ctx, nil)
	if err != nil {
		log.Errorf("[SeqSender] Error getting results for all tx: %v", err)
		return err
	}

	// Check and update tx status
	for _, result := range results {
		txSequence, exists := s.ethTransactions[result.ID]
		if exists {
			if txSequence.Status != result.Status.String() {
				log.Debugf("[SeqSender] update transaction %v state to %s", result.ID, result.Status.String())
				txSequence.Status = result.Status.String()
			} else {
				log.Debugf("[SeqSender] transaction %v keep state %s", result.ID, result.Status.String())
			}
		} else {
			log.Debugf("[SeqSender] transaction %v does not exist in memory structure. Adding it", result.ID)
			// TODO: from/to batch info?
			s.ethTransactions[result.ID] = ethTxData{
				Status: result.Status.String(),
			}
		}
	}

	// Save updated sequences
	// err = s.saveSentSequencesTransactions()
	// if err != nil {
	// 	log.Fatalf("[SeqSender] error saving tx sequence sent, error: %v", err)
	// }

	return nil
}

func (s *SequenceSender) tryToSendSequence(ctx context.Context, ticker *time.Ticker) {
	// Update latest virtual batch
	log.Debugf("[SeqSender] updating virtual batch")
	err := s.updateLatestVirtualBatch()
	if err != nil {
		waitTick(ctx, ticker)
		return
	}

	// Check and update the state of transactions
	log.Debugf("[SeqSender] updating tx results")
	err = s.updateEthTxResults(ctx)
	if err != nil {
		waitTick(ctx, ticker)
		return
	}

	// TODO: Add time margin

	// Check if should send sequence to L1
	log.Debugf("[SeqSender] getting sequences to send")
	sequences, err := s.getSequencesToSend(ctx)
	if err != nil || len(sequences) == 0 {
		if err != nil {
			log.Errorf("[SeqSender] error getting sequences: %v", err)
		} else {
			log.Debugf("[SeqSender] waiting for sequences to be worth sending to L1")
		}
		waitTick(ctx, ticker)
		return
	}

	// Send sequences to L1
	sequenceCount := len(sequences)
	firstSequence := sequences[0]
	lastSequence := sequences[sequenceCount-1]
	log.Infof("[SeqSender] sending sequences to L1. From batch %d to batch %d", firstSequence.BatchNumber, lastSequence.BatchNumber)

	// data := make([]byte, 0)
	// for b := firstSequence.BatchNumber; b <= lastSequence.BatchNumber; b++ {
	// 	data = append(data, s.sequenceData[b].batch.BatchL2Data...)
	// }
	// to := s.cfg.SenderAddress //common.HexToAddress("0x0001")

	// Add sequence
	to, data, err := s.etherman.BuildSequenceBatchesTxData(s.cfg.SenderAddress, sequences, s.cfg.L2Coinbase)
	if err != nil {
		log.Errorf("[SeqSender] error estimating new sequenceBatches to add to ethtxmanager: ", err)
		return
	}

	// Add sequence tx
	log.Debugf("[SeqSender] ethTxman Add, to: %v", to)
	txHash, err := s.ethTxManager.Add(ctx, to, nil, big.NewInt(0), data)
	if err != nil {
		log.Errorf("[SeqSender] error adding sequence to ethtxmanager: %v", err)
		return
	}

	// Add new eth tx
	txData := ethTxData{
		Status:    string(ethtxmanager.MonitoredTxStatusCreated),
		FromBatch: firstSequence.BatchNumber,
		ToBatch:   lastSequence.BatchNumber,
	}
	s.ethTransactions[txHash] = txData
	s.latestSentToL1Batch = lastSequence.BatchNumber

	// Save sent sequences
	err = s.saveSentSequencesTransactions()
	if err != nil {
		log.Fatalf("[SeqSender] error saving tx sequence sent, error: %v", err)
	}

	s.printEthTxs()
}

// getSequencesToSend generates an array of sequences to be send to L1.
// If the array is empty, it doesn't necessarily mean that there are no sequences to be sent,
// it could be that it's not worth it to do so yet.
func (s *SequenceSender) getSequencesToSend(ctx context.Context) ([]types.Sequence, error) {
	// Add sequences until too big for a single L1 tx or last batch is reached
	sequences := []types.Sequence{}
	for i := 0; i < len(s.sequenceList); i++ {
		batchNumber := s.sequenceList[i]
		if batchNumber <= s.latestVirtualBatch || batchNumber <= s.latestSentToL1Batch {
			continue
		}

		// Check if the next batch belongs to a new forkid, in this case we need to stop sequencing as we need to
		// wait the upgrade of forkid is completed and s.cfg.NumBatchForkIdUpgrade is disabled (=0) again
		if (s.cfg.ForkUpgradeBatchNumber != 0) && (batchNumber == (s.cfg.ForkUpgradeBatchNumber + 1)) {
			return nil, fmt.Errorf("[SeqSender] aborting sequencing process as we reached the batch %d where a new forkid is applied (upgrade)", s.cfg.ForkUpgradeBatchNumber+1)
		}

		// Check if batch is closed
		if !s.sequenceData[batchNumber].batchClosed {
			// Reached current wip batch
			break
		}

		// Add new sequence
		batch := *s.sequenceData[batchNumber].batch
		sequences = append(sequences, batch)

		// Check if can be send
		tx, err := s.etherman.EstimateGasSequenceBatches(s.cfg.SenderAddress, sequences, s.cfg.L2Coinbase)

		if err == nil && tx.Size() > s.cfg.MaxTxSizeForL1 {
			log.Infof("[SeqSender] oversized Data on TX oldHash %s (txSize %d > %d)", tx.Hash(), tx.Size(), s.cfg.MaxTxSizeForL1)
			err = ErrOversizedData
		}

		if err != nil {
			log.Infof("[SeqSender] handling estimate gas send sequence error: %v", err)
			sequences, err = s.handleEstimateGasSendSequenceErr(ctx, sequences, batchNumber, err)
			if sequences != nil {
				// Handling the error gracefully, re-processing the sequence as a sanity check
				_, err = s.etherman.EstimateGasSequenceBatches(s.cfg.SenderAddress, sequences, s.cfg.L2Coinbase)
				return sequences, err
			}
			return sequences, err
		} else {
			log.Debugf("[SeqSender] Estimate Gas adding batch %d tx size %d: error %v", batchNumber, tx.Size(), err)
		}

		// Check if the current batch is the last before a change to a new forkid, in this case we need to close and send the sequence to L1
		if (s.cfg.ForkUpgradeBatchNumber != 0) && (batchNumber == (s.cfg.ForkUpgradeBatchNumber)) {
			log.Infof("[SeqSender] sequence should be sent to L1, as we have reached the batch %d from which a new forkid is applied (upgrade)", s.cfg.ForkUpgradeBatchNumber)
			return sequences, nil
		}
	}

	// Reached latest batch. Decide if it's worth to send the sequence, or wait for new batches
	if len(sequences) == 0 {
		log.Info("[SeqSender] no batches to be sequenced")
		return nil, nil
	}

	// lastBatchVirtualizationTime, err := s.state.GetTimeForLatestBatchVirtualization(ctx, nil)
	// if err != nil && !errors.Is(err, state.ErrNotFound) {
	// 	log.Warnf("[SeqSender] failed to get last l1 interaction time, err: %v. Sending sequences as a conservative approach", err)
	// 	return sequences, nil
	// }
	// if lastBatchVirtualizationTime.Before(time.Now().Add(-s.cfg.LastBatchVirtualizationTimeMaxWaitPeriod.Duration)) {
	// 	log.Info("[SeqSender] sequence should be sent to L1, because too long since didn't send anything to L1")
	// 	return sequences, nil
	// }

	return sequences, nil
	// log.Info("[SeqSender] not enough time has passed since last batch was virtualized, and the sequence could be bigger")
	// return nil, nil
}

// handleEstimateGasSendSequenceErr handles an error on the estimate gas. It will return:
// nil, error: impossible to handle gracefully
// sequence, nil: handled gracefully. Potentially manipulating the sequences
// nil, nil: a situation that requires waiting
func (s *SequenceSender) handleEstimateGasSendSequenceErr(
	ctx context.Context,
	sequences []types.Sequence,
	currentBatchNumToSequence uint64,
	err error,
) ([]types.Sequence, error) {
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

	// Unknown error
	if len(sequences) == 1 {
		// TODO: gracefully handle this situation by creating an L2 reorg
		log.Errorf(
			"Error when estimating gas for BatchNum %d (alone in the sequences): %v",
			currentBatchNumToSequence, err,
		)
	}
	// Remove the latest item and send the sequences
	log.Infof(
		"Done building sequences, selected batches to %d. Batch %d excluded due to unknown error: %v",
		currentBatchNumToSequence, currentBatchNumToSequence+1, err,
	)
	sequences = sequences[:len(sequences)-1]

	return sequences, nil
}

func isDataForEthTxTooBig(err error) bool {
	return errors.Is(err, etherman.ErrGasRequiredExceedsAllowance) ||
		errors.Is(err, ErrOversizedData) ||
		errors.Is(err, etherman.ErrContentLengthTooLarge)
}

func waitTick(ctx context.Context, ticker *time.Ticker) {
	select {
	case <-ticker.C:
		// nothing
	case <-ctx.Done():
		return
	}
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
	err = json.Unmarshal(data, &s.ethTransactions)
	if err != nil {
		log.Errorf("[SeqSender] error decoding data from %s: %v", s.cfg.SequencesTxFileName, err)
		return err
	}

	return nil
}

// saveSentSequencesTransactions saves memory structure into persistent file
func (s *SequenceSender) saveSentSequencesTransactions() error {
	var err error

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
	err = encoder.Encode(s.ethTransactions)
	if err != nil {
		log.Errorf("[SeqSender] error writing file %s: %v", fileName, err)
		return err
	}

	// Delete the old file
	if _, err := os.Stat(s.cfg.SequencesTxFileName); err == nil {
		err = os.Remove(s.cfg.SequencesTxFileName)
		if err != nil {
			log.Errorf("[SeqSender] error deleting file %s: %v", s.cfg.SequencesTxFileName, err)
			return err
		}
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
		} else {
			s.validStream = true
		}

		// Latest stream batch
		s.latestStreamBatch = l2BlockStart.BatchNumber

		if !s.validStream {
			return nil
		}

		// Manage if it is a new block or new batch
		if l2BlockStart.BatchNumber == s.wipBatch {
			// New block in the current batch
			if s.wipBatch == s.fromStreamBatch+1 {
				// Initial case after startup
				s.addNewSequenceBatch(l2BlockStart)
			}
		} else if l2BlockStart.BatchNumber > s.wipBatch {
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
		s.prevBlockHash = l2BlockEnd.BlockHash

		if !s.validStream {
			return nil
		}

		// Add end block data
		s.addInfoSequenceBatch(l2BlockEnd)

	case state.EntryTypeUpdateGER:
		// Handle stream entry: Update GER
		// TODO: What should I do
	}

	return nil
}

// closeSequenceBatch closes the current batch
func (s *SequenceSender) closeSequenceBatch() error {
	s.mutexSequence.Lock()
	log.Debugf("[SeqSender] Closing batch %d", s.wipBatch)

	data := s.sequenceData[s.wipBatch]
	if data != nil {
		data.batchClosed = true
		// data.batch.PrevBlockHash = s.prevBlockHash

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
	if s.sequenceData[l2BlockStart.BatchNumber] == nil {
		log.Infof("[SeqSender] ...new batch, number %d", l2BlockStart.BatchNumber)

		// Create sequence
		sequence := types.Sequence{
			GlobalExitRoot: l2BlockStart.GlobalExitRoot,
			Timestamp:      l2BlockStart.Timestamp,
			BatchNumber:    l2BlockStart.BatchNumber,
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
	}
	s.mutexSequence.Unlock()
}

// addInfoSequenceBatch adds info
func (s *SequenceSender) addInfoSequenceBatch(l2BlockEnd state.DSL2BlockEnd) {
	s.mutexSequence.Lock()

	// Current batch
	wipBatch := s.sequenceData[s.wipBatch].batch
	wipBatch.StateRoot = l2BlockEnd.StateRoot

	s.mutexSequence.Unlock()
}

// addNewBatchL2Block adds a new L2 block to the work in progress batch
func (s *SequenceSender) addNewBatchL2Block(l2BlockStart state.DSL2BlockStart) {
	s.mutexSequence.Lock()
	log.Infof("[SeqSender] .....new L2 block, number %d (batch %d)", l2BlockStart.L2BlockNumber, l2BlockStart.BatchNumber)

	// Current batch
	wipBatchRaw := s.sequenceData[s.wipBatch].batchRaw

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
	s.mutexSequence.Unlock()
}

// addNewBlockTx adds a new Tx to the current L2 block
func (s *SequenceSender) addNewBlockTx(l2Tx state.DSL2Transaction) {
	s.mutexSequence.Lock()
	log.Infof("[SeqSender] ........new tx, length %d", l2Tx.EncodedLength)
	log.Debugf("[SeqSender] ........encoded: [%x]", l2Tx.Encoded)

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
		log.Debugf("[SeqSender] latest virtual batch %d", s.latestVirtualBatch)
	}
	return nil
}

// printSequences prints the current batches sequence (or just a selected batch) in the memory structure
func (s *SequenceSender) printSequences(selectBatch uint64, showBlock bool, showTx bool) {
	for i := 0; i < len(s.sequenceList); i++ {
		// Batch info
		batchNumber := s.sequenceList[i]
		if selectBatch == 0 || selectBatch == batchNumber {
			seq := s.sequenceData[batchNumber]

			var raw *state.BatchRawV2
			if seq != nil {
				raw = seq.batchRaw
			} else {
				log.Debugf("[SeqSender] // batch number %d not found in the map!", batchNumber)
				continue
			}

			log.Debugf("[SeqSender] // seq %d: batch %d (closed? %t, GER: %x...)", i, batchNumber, seq.batchClosed, seq.batch.GlobalExitRoot[:8])
			printBatch(raw, showBlock, showTx)
		}
	}
}

// printEthTxs prints the current L1 transactions in the memory structure
func (s *SequenceSender) printEthTxs() {
	for hash, data := range s.ethTransactions {
		log.Debugf("[SeqSender] // tx hash %x... (status: %s, from: %d, to: %d) hash %x", hash[:4], data.Status, data.FromBatch, data.ToBatch, hash)
	}
}

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
					log.Debugf("[SeqSender] //       tx(%d) effPct: %d, encoded: %t, Tx: %+v, v: %v, r: %v, s: %v", iTx, tx.EfficiencyPercentage, tx.TxAlreadyEncoded, tx.Tx, v, r, s)
				}
			}
		}
		if lastBlock != nil {
			log.Debugf("[SeqSender] //    block last (indL1info: %d, delta-timestamp: %d, #L2txs: %d)", lastBlock.DeltaTimestamp, lastBlock.DeltaTimestamp, len(lastBlock.Transactions))
		}
	}
}
