package main

import (
	"math/big"
	"sync"
	"time"

	"github.com/0xPolygonHermez/zkevm-data-streamer/datastreamer"
	streamlog "github.com/0xPolygonHermez/zkevm-data-streamer/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/state"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/state/datastream"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/protobuf/proto"
)

const (
	streamServer   = "datastream.internal.zkevm-rpc.com:6900"
	dataStreamType = 1
	batchNumber    = 55667
)

type sequenceData struct {
	batchClosed bool
	batch       *types.Sequence
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
	Gas             uint64                              `json:"gas"`
}

type ethTxAdditionalData struct {
	GasPrice      *big.Int `json:"gasPrice,omitempty"`
	RevertMessage string   `json:"revertMessage,omitempty"`
}

type SequenceSenderMock struct {
	latestVirtualBatch  uint64                     // Latest virtualized batch obtained from L1
	latestSentToL1Batch uint64                     // Latest batch sent to L1
	wipBatch            uint64                     // Work in progress batch
	sequenceList        []uint64                   // Sequence of batch number to be send to L1
	sequenceData        map[uint64]*sequenceData   // All the batch data indexed by batch number
	mutexSequence       sync.Mutex                 // Mutex to access sequenceData and sequenceList
	ethTransactions     map[common.Hash]*ethTxData // All the eth tx sent to L1 indexed by hash
	ethTxData           map[common.Hash][]byte     // Tx data send to or received from L1
	validStream         bool                       // Not valid while receiving data before the desired batch
	fromStreamBatch     uint64                     // Initial batch to connect to the streaming
	latestStreamBatch   uint64                     // Latest batch received by the streaming
	seqSendingStopped   bool                       // If there is a critical error
	streamClient        *datastreamer.StreamClient
	finish              bool
}

func main() {
	// Data stream client logs
	streamLogConfig := streamlog.Config{
		Environment: streamlog.LogEnvironment("development"),
		Level:       "info",
		Outputs:     []string{"stderr"},
	}

	log.Init(log.Config{
		Environment: log.LogEnvironment(streamLogConfig.Environment),
		Level:       streamLogConfig.Level,
		Outputs:     streamLogConfig.Outputs,
	})

	s := SequenceSenderMock{
		ethTransactions:   make(map[common.Hash]*ethTxData),
		ethTxData:         make(map[common.Hash][]byte),
		sequenceData:      make(map[uint64]*sequenceData),
		validStream:       false,
		latestStreamBatch: 0,
		seqSendingStopped: false,
		finish:            false,
	}

	log.Info("Creating data stream client....")

	var err error
	s.streamClient, err = datastreamer.NewClientWithLogsConfig(streamServer, dataStreamType, streamLogConfig)
	if err != nil {
		log.Fatalf("failed to create stream client, error: %v", err)
	}
	log.Info("Data stream client created.")

	s.streamClient.SetProcessEntryFunc(s.handleReceivedDataStream)

	s.latestVirtualBatch = batchNumber - 1
	s.fromStreamBatch = batchNumber - 1

	// Current batch to sequence
	s.wipBatch = s.latestVirtualBatch + 1
	s.latestSentToL1Batch = s.latestVirtualBatch

	// Start datastream client
	err = s.streamClient.Start()
	if err != nil {
		log.Fatalf("failed to start stream client, error: %v", err)
	}

	bookmark := &datastream.BookMark{
		Type:  datastream.BookmarkType_BOOKMARK_TYPE_BATCH,
		Value: s.fromStreamBatch,
	}

	marshalledBookmark, err := proto.Marshal(bookmark)
	if err != nil {
		log.Fatalf("failed to marshal bookmark, error: %v", err)
	}

	log.Infof("stream client from bookmark %v", bookmark)

	// Current batch to sequence
	s.wipBatch = s.latestVirtualBatch + 1
	s.latestSentToL1Batch = s.latestVirtualBatch

	// Start receiving the streaming
	err = s.streamClient.ExecCommandStartBookmark(marshalledBookmark)
	if err != nil {
		log.Fatalf("failed to connect to the streaming: %v", err)
	}

	// Loop to keep the program running
	for !s.finish {
		time.Sleep(1 * time.Second)
	}
}

func (s *SequenceSenderMock) handleReceivedDataStream(e *datastreamer.FileEntry, c *datastreamer.StreamClient, ss *datastreamer.StreamServer) error {

	if !s.finish {
		dsType := datastream.EntryType(e.Type)

		switch dsType {
		case datastream.EntryType_ENTRY_TYPE_L2_BLOCK:
			// Handle stream entry: L2Block
			l2Block := &datastream.L2Block{}

			err := proto.Unmarshal(e.Data, l2Block)
			if err != nil {
				log.Errorf("error unmarshalling L2Block: %v", err)
				return err
			}

			// Already virtualized
			if l2Block.BatchNumber <= s.fromStreamBatch {
				if l2Block.BatchNumber != s.latestStreamBatch {
					log.Infof("skipped! batch already virtualized, number %d", l2Block.BatchNumber)
				}
			} else if !s.validStream && l2Block.BatchNumber == s.fromStreamBatch+1 {
				// Initial case after startup
				s.addNewSequenceBatch(l2Block)
				s.validStream = true
			} else {
				// Handle whether it's only a new block or also a new batch
				if l2Block.BatchNumber > s.wipBatch {
					// Create new sequential batch
					s.addNewSequenceBatch(l2Block)
				}
			}

			// Latest stream batch
			s.latestStreamBatch = l2Block.BatchNumber
			if !s.validStream {
				return nil
			}

			// Add L2 block
			s.addNewBatchL2Block(l2Block)

		case datastream.EntryType_ENTRY_TYPE_TRANSACTION:
			// Handle stream entry: Transaction
			if !s.validStream {
				return nil
			}

			l2Tx := &datastream.Transaction{}
			err := proto.Unmarshal(e.Data, l2Tx)
			if err != nil {
				log.Errorf("error unmarshalling Transaction: %v", err)
				return err
			}

			// Add tx data
			s.addNewBlockTx(l2Tx)

		case datastream.EntryType_ENTRY_TYPE_BATCH_START:
			// Handle stream entry: BatchStart
			if !s.validStream {
				return nil
			}

			batch := &datastream.BatchStart{}
			err := proto.Unmarshal(e.Data, batch)
			if err != nil {
				log.Errorf("error unmarshalling BatchStart: %v", err)
				return err
			}

			// Add batch start data
			s.addInfoSequenceBatchStart(batch)

		case datastream.EntryType_ENTRY_TYPE_BATCH_END:
			// Handle stream entry: BatchEnd
			if !s.validStream {
				return nil
			}

			batch := &datastream.BatchEnd{}
			err := proto.Unmarshal(e.Data, batch)
			if err != nil {
				log.Errorf("error unmarshalling BatchEnd: %v", err)
				return err
			}

			// Add batch end data
			s.addInfoSequenceBatchEnd(batch)

			// Close current batch
			err = s.closeSequenceBatch()
			if err != nil {
				log.Fatalf("error closing wip batch")
				return err
			}
		}
	}

	return nil
}

// addNewSequenceBatch adds a new batch to the sequence
func (s *SequenceSenderMock) addNewSequenceBatch(l2Block *datastream.L2Block) {
	s.mutexSequence.Lock()
	defer s.mutexSequence.Unlock()
	log.Infof("...new batch, number %d", l2Block.BatchNumber)

	if l2Block.BatchNumber > s.wipBatch+1 {
		s.logFatalf("new batch number (%d) is not consecutive to the current one (%d)", l2Block.BatchNumber, s.wipBatch)
	} else if l2Block.BatchNumber < s.wipBatch {
		s.logFatalf("new batch number (%d) is lower than the current one (%d)", l2Block.BatchNumber, s.wipBatch)
	}

	// Create sequence
	sequence := types.Sequence{
		GlobalExitRoot:       common.BytesToHash(l2Block.GlobalExitRoot),
		LastL2BLockTimestamp: l2Block.Timestamp,
		BatchNumber:          l2Block.BatchNumber,
		LastCoinbase:         common.BytesToAddress(l2Block.Coinbase),
	}

	// Add to the list
	s.sequenceList = append(s.sequenceList, l2Block.BatchNumber)

	// Create initial data
	batchRaw := state.BatchRawV2{}
	data := sequenceData{
		batchClosed: false,
		batch:       &sequence,
		batchRaw:    &batchRaw,
	}
	s.sequenceData[l2Block.BatchNumber] = &data

	// Update wip batch
	s.wipBatch = l2Block.BatchNumber

}

// addInfoSequenceBatchStart adds info from the batch start
func (s *SequenceSenderMock) addInfoSequenceBatchStart(batch *datastream.BatchStart) {
	s.mutexSequence.Lock()
	log.Infof("batch %d (%s) Start: type %d forkId %d chainId %d", batch.Number, datastream.BatchType_name[int32(batch.Type)], batch.Type, batch.ForkId, batch.ChainId)

	// Current batch
	data := s.sequenceData[s.wipBatch]
	if data != nil {
		wipBatch := data.batch
		if wipBatch.BatchNumber+1 != batch.Number {
			s.logFatalf("batch start number (%d) does not match the current consecutive one (%d)", batch.Number, wipBatch.BatchNumber)
		}
	}

	s.mutexSequence.Unlock()
}

// addInfoSequenceBatchEnd adds info from the batch end
func (s *SequenceSenderMock) addInfoSequenceBatchEnd(batch *datastream.BatchEnd) {
	s.mutexSequence.Lock()

	// Current batch
	data := s.sequenceData[s.wipBatch]
	if data != nil {
		wipBatch := data.batch
		if wipBatch.BatchNumber == batch.Number {
			wipBatch.StateRoot = common.BytesToHash(batch.StateRoot)
		} else {
			s.logFatalf("batch end number (%d) does not match the current one (%d)", batch.Number, wipBatch.BatchNumber)
		}
	}

	s.mutexSequence.Unlock()
}

// addNewBatchL2Block adds a new L2 block to the work in progress batch
func (s *SequenceSenderMock) addNewBatchL2Block(l2Block *datastream.L2Block) {
	s.mutexSequence.Lock()
	log.Infof(".....new L2 block, number %d (batch %d)", l2Block.Number, l2Block.BatchNumber)

	// Current batch
	data := s.sequenceData[s.wipBatch]
	if data != nil {
		wipBatchRaw := data.batchRaw
		data.batch.LastL2BLockTimestamp = l2Block.Timestamp
		// Sanity check: should be the same coinbase within the batch
		if common.BytesToAddress(l2Block.Coinbase) != data.batch.LastCoinbase {
			s.logFatalf("coinbase changed within the batch! (Previous %v, Current %v)", data.batch.LastCoinbase, common.BytesToAddress(l2Block.Coinbase))
		}
		data.batch.LastCoinbase = common.BytesToAddress(l2Block.Coinbase)
		data.batch.StateRoot = common.BytesToHash(l2Block.StateRoot)

		// New L2 block raw
		newBlockRaw := state.L2BlockRaw{}

		// Add L2 block
		wipBatchRaw.Blocks = append(wipBatchRaw.Blocks, newBlockRaw)

		// Update batch timestamp
		data.batch.LastL2BLockTimestamp = l2Block.Timestamp

		// Get current L2 block
		_, blockRaw := s.getWipL2Block()
		if blockRaw == nil {
			log.Debugf("wip block %d not found!")
			return
		}

		// Fill in data
		blockRaw.DeltaTimestamp = l2Block.DeltaTimestamp
		blockRaw.IndexL1InfoTree = l2Block.L1InfotreeIndex
	}

	s.mutexSequence.Unlock()
}

// addNewBlockTx adds a new Tx to the current L2 block
func (s *SequenceSenderMock) addNewBlockTx(l2Tx *datastream.Transaction) {
	s.mutexSequence.Lock()
	log.Debugf("........new tx, length %d EGP %d SR %x..", len(l2Tx.Encoded), l2Tx.EffectiveGasPricePercentage, l2Tx.ImStateRoot[:8])

	// Current L2 block
	_, blockRaw := s.getWipL2Block()

	// New Tx raw
	tx, err := state.DecodeTx(common.Bytes2Hex(l2Tx.Encoded))
	if err != nil {
		log.Fatalf("[SeqSender] error decoding tx! %v", err)
		return
	}

	l2TxRaw := state.L2TxRaw{
		EfficiencyPercentage: uint8(l2Tx.EffectiveGasPricePercentage),
		TxAlreadyEncoded:     false,
		Tx:                   tx,
	}

	// Add Tx
	blockRaw.Transactions = append(blockRaw.Transactions, l2TxRaw)
	s.mutexSequence.Unlock()
}

// closeSequenceBatch closes the current batch
func (s *SequenceSenderMock) closeSequenceBatch() error {
	s.mutexSequence.Lock()
	defer s.mutexSequence.Unlock()

	log.Infof("closing batch %d", s.wipBatch)

	data := s.sequenceData[s.wipBatch]
	if data != nil {
		data.batchClosed = true

		var err error
		data.batch.BatchL2Data, err = state.EncodeBatchV2(data.batchRaw)
		if err != nil {
			log.Errorf("error closing and encoding the batch %d: %v", s.wipBatch, err)
			return err
		}
	}

	// Log batch data
	log.Infof("batch %d closed, %d blocks", s.wipBatch, len(data.batchRaw.Blocks))

	// Log batchl2data
	log.Infof("batch %d L2 data: %x", s.wipBatch, data.batch.BatchL2Data)

	s.finish = true

	return nil
}

// getWipL2Block returns index of the array and pointer to the current L2 block (helper func)
func (s *SequenceSenderMock) getWipL2Block() (uint64, *state.L2BlockRaw) {
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

// logFatalf logs error, activates flag to stop sequencing, and remains in an infinite loop
func (s *SequenceSenderMock) logFatalf(template string, args ...interface{}) {
	s.seqSendingStopped = true
	log.Errorf(template, args...)
	log.Errorf("sequence sending stopped.")
	for {
		time.Sleep(1 * time.Second)
	}
}
