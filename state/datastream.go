package state

import (
	"context"
	"encoding/binary"
	"math/big"

	"github.com/0xPolygonHermez/zkevm-data-streamer/datastreamer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/jackc/pgx/v4"
)

const (
	// StreamTypeSequencer represents a Sequencer stream
	StreamTypeSequencer datastreamer.StreamType = 1
	// EntryTypeBookMark represents a bookmark entry
	EntryTypeBookMark datastreamer.EntryType = datastreamer.EtBookmark
	// EntryTypeL2BlockStart represents a L2 block start
	EntryTypeL2BlockStart datastreamer.EntryType = 1
	// EntryTypeL2Tx represents a L2 transaction
	EntryTypeL2Tx datastreamer.EntryType = 2
	// EntryTypeL2BlockEnd represents a L2 block end
	EntryTypeL2BlockEnd datastreamer.EntryType = 3
	// EntryTypeUpdateGER represents a GER update
	EntryTypeUpdateGER datastreamer.EntryType = 4
	// BookMarkTypeL2Block represents a L2 block bookmark
	BookMarkTypeL2Block byte = 0
	// BookMarkTypeBatch represents a batch
	BookMarkTypeBatch byte = 1
	// SystemSC is the system smart contract address
	SystemSC = "0x000000000000000000000000000000005ca1ab1e"
	// posConstant is the constant used to compute the position of the intermediate state root
	posConstant = 1
)

// DSBatch represents a data stream batch
type DSBatch struct {
	Batch
	ForkID uint16
}

// DSFullBatch represents a data stream batch ant its L2 blocks
type DSFullBatch struct {
	DSBatch
	L2Blocks []DSL2FullBlock
}

// DSL2FullBlock represents a data stream L2 full block and its transactions
type DSL2FullBlock struct {
	DSL2Block
	Txs []DSL2Transaction
}

// DSL2Block is a full l2 block
type DSL2Block struct {
	BatchNumber    uint64         // 8 bytes
	L2BlockNumber  uint64         // 8 bytes
	Timestamp      int64          // 8 bytes
	L1BlockHash    common.Hash    // 32 bytes
	GlobalExitRoot common.Hash    // 32 bytes
	Coinbase       common.Address // 20 bytes
	ForkID         uint16         // 2 bytes
	BlockHash      common.Hash    // 32 bytes
	StateRoot      common.Hash    // 32 bytes
}

// DSL2BlockStart represents a data stream L2 block start
type DSL2BlockStart struct {
	BatchNumber    uint64         // 8 bytes
	L2BlockNumber  uint64         // 8 bytes
	Timestamp      int64          // 8 bytes
	L1BlockHash    common.Hash    // 32 bytes
	GlobalExitRoot common.Hash    // 32 bytes
	Coinbase       common.Address // 20 bytes
	ForkID         uint16         // 2 bytes
}

// Encode returns the encoded DSL2BlockStart as a byte slice
func (b DSL2BlockStart) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = binary.LittleEndian.AppendUint64(bytes, b.BatchNumber)
	bytes = binary.LittleEndian.AppendUint64(bytes, b.L2BlockNumber)
	bytes = binary.LittleEndian.AppendUint64(bytes, uint64(b.Timestamp))
	bytes = append(bytes, b.L1BlockHash.Bytes()...)
	bytes = append(bytes, b.GlobalExitRoot.Bytes()...)
	bytes = append(bytes, b.Coinbase.Bytes()...)
	bytes = binary.LittleEndian.AppendUint16(bytes, b.ForkID)
	return bytes
}

// Decode decodes the DSL2BlockStart from a byte slice
func (b DSL2BlockStart) Decode(data []byte) DSL2BlockStart {
	b.BatchNumber = binary.LittleEndian.Uint64(data[0:8])
	b.L2BlockNumber = binary.LittleEndian.Uint64(data[8:16])
	b.Timestamp = int64(binary.LittleEndian.Uint64(data[16:24]))
	b.L1BlockHash = common.BytesToHash(data[24:56])
	b.GlobalExitRoot = common.BytesToHash(data[56:88])
	b.Coinbase = common.BytesToAddress(data[88:108])
	b.ForkID = binary.LittleEndian.Uint16(data[108:110])
	return b
}

// DSL2Transaction represents a data stream L2 transaction
type DSL2Transaction struct {
	L2BlockNumber               uint64      // Not included in the encoded data
	EffectiveGasPricePercentage uint8       // 1 byte
	IsValid                     uint8       // 1 byte
	StateRoot                   common.Hash // 32 bytes
	EncodedLength               uint32      // 4 bytes
	Encoded                     []byte
}

// Encode returns the encoded DSL2Transaction as a byte slice
func (l DSL2Transaction) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = append(bytes, l.EffectiveGasPricePercentage)
	bytes = append(bytes, l.IsValid)
	bytes = append(bytes, l.StateRoot[:]...)
	bytes = binary.LittleEndian.AppendUint32(bytes, l.EncodedLength)
	bytes = append(bytes, l.Encoded...)
	return bytes
}

// Decode decodes the DSL2Transaction from a byte slice
func (l DSL2Transaction) Decode(data []byte) DSL2Transaction {
	l.EffectiveGasPricePercentage = data[0]
	l.IsValid = data[1]
	l.StateRoot = common.BytesToHash(data[2:34])
	l.EncodedLength = binary.LittleEndian.Uint32(data[34:38])
	l.Encoded = data[38:]
	return l
}

// DSL2BlockEnd represents a L2 block end
type DSL2BlockEnd struct {
	L2BlockNumber uint64      // 8 bytes
	BlockHash     common.Hash // 32 bytes
	StateRoot     common.Hash // 32 bytes
}

// Encode returns the encoded DSL2BlockEnd as a byte slice
func (b DSL2BlockEnd) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = binary.LittleEndian.AppendUint64(bytes, b.L2BlockNumber)
	bytes = append(bytes, b.BlockHash[:]...)
	bytes = append(bytes, b.StateRoot[:]...)
	return bytes
}

// Decode decodes the DSL2BlockEnd from a byte slice
func (b DSL2BlockEnd) Decode(data []byte) DSL2BlockEnd {
	b.L2BlockNumber = binary.LittleEndian.Uint64(data[0:8])
	b.BlockHash = common.BytesToHash(data[8:40])
	b.StateRoot = common.BytesToHash(data[40:72])
	return b
}

// DSBookMark represents a data stream bookmark
type DSBookMark struct {
	Type  byte
	Value uint64
}

// Encode returns the encoded DSBookMark as a byte slice
func (b DSBookMark) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = append(bytes, b.Type)
	bytes = binary.LittleEndian.AppendUint64(bytes, b.Value)
	return bytes
}

// Decode decodes the DSBookMark from a byte slice
func (b DSBookMark) Decode(data []byte) DSBookMark {
	b.Type = data[0]
	b.Value = binary.LittleEndian.Uint64(data[1:9])
	return b
}

// DSUpdateGER represents a data stream GER update
type DSUpdateGER struct {
	BatchNumber    uint64         // 8 bytes
	Timestamp      int64          // 8 bytes
	GlobalExitRoot common.Hash    // 32 bytes
	Coinbase       common.Address // 20 bytes
	ForkID         uint16         // 2 bytes
	StateRoot      common.Hash    // 32 bytes
}

// Encode returns the encoded DSUpdateGER as a byte slice
func (g DSUpdateGER) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = binary.LittleEndian.AppendUint64(bytes, g.BatchNumber)
	bytes = binary.LittleEndian.AppendUint64(bytes, uint64(g.Timestamp))
	bytes = append(bytes, g.GlobalExitRoot[:]...)
	bytes = append(bytes, g.Coinbase[:]...)
	bytes = binary.LittleEndian.AppendUint16(bytes, g.ForkID)
	bytes = append(bytes, g.StateRoot[:]...)
	return bytes
}

// Decode decodes the DSUpdateGER from a byte slice
func (g DSUpdateGER) Decode(data []byte) DSUpdateGER {
	g.BatchNumber = binary.LittleEndian.Uint64(data[0:8])
	g.Timestamp = int64(binary.LittleEndian.Uint64(data[8:16]))
	g.GlobalExitRoot = common.BytesToHash(data[16:48])
	g.Coinbase = common.BytesToAddress(data[48:68])
	g.ForkID = binary.LittleEndian.Uint16(data[68:70])
	g.StateRoot = common.BytesToHash(data[70:102])
	return g
}

// DSState gathers the methods required to interact with the data stream state.
type DSState interface {
	GetDSGenesisBlock(ctx context.Context, dbTx pgx.Tx) (*DSL2Block, error)
	GetDSBatches(ctx context.Context, firstBatchNumber, lastBatchNumber uint64, readWIPBatch bool, dbTx pgx.Tx) ([]*DSBatch, error)
	GetDSL2Blocks(ctx context.Context, firstBatchNumber, lastBatchNumber uint64, dbTx pgx.Tx) ([]*DSL2Block, error)
	GetDSL2Transactions(ctx context.Context, firstL2Block, lastL2Block uint64, dbTx pgx.Tx) ([]*DSL2Transaction, error)
	GetStorageAt(ctx context.Context, address common.Address, position *big.Int, root common.Hash) (*big.Int, error)
	GetLastL2BlockHeader(ctx context.Context, dbTx pgx.Tx) (*L2Header, error)
	GetVirtualBatchParentHash(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) (common.Hash, error)
	GetForcedBatchParentHash(ctx context.Context, forcedBatchNumber uint64, dbTx pgx.Tx) (common.Hash, error)
	GetVirtualBatch(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) (*VirtualBatch, error)
}

// GetSystemSCPosition computes the position of the intermediate state root for the system smart contract
func GetSystemSCPosition(blockNumber uint64) []byte {
	v1 := big.NewInt(0).SetUint64(blockNumber).Bytes()
	v2 := big.NewInt(0).SetUint64(uint64(posConstant)).Bytes()

	// Add 0s to make v1 and v2 32 bytes long
	for len(v1) < 32 {
		v1 = append([]byte{0}, v1...)
	}
	for len(v2) < 32 {
		v2 = append([]byte{0}, v2...)
	}

	return keccak256.Hash(v1, v2)
}

/*

// computeFullBatches computes the full batches
func computeFullBatches(batches []*DSBatch, l2Blocks []*DSL2Block, l2Txs []*DSL2Transaction) []*DSFullBatch {
	prevL2BlockNumber := uint64(0)
	currentL2Block := 0
	currentL2Tx := 0

	fullBatches := make([]*DSFullBatch, 0)

	for _, batch := range batches {
		fullBatch := &DSFullBatch{
			DSBatch: *batch,
		}

		for i := currentL2Block; i < len(l2Blocks); i++ {
			l2Block := l2Blocks[i]

			if prevL2BlockNumber != 0 && l2Block.L2BlockNumber <= prevL2BlockNumber {
				continue
			}

			if l2Block.BatchNumber == batch.BatchNumber {
				fullBlock := DSL2FullBlock{
					DSL2Block: *l2Block,
				}

				for j := currentL2Tx; j < len(l2Txs); j++ {
					l2Tx := l2Txs[j]
					if l2Tx.L2BlockNumber == l2Block.L2BlockNumber {
						fullBlock.Txs = append(fullBlock.Txs, *l2Tx)
						currentL2Tx++
					}
					if l2Tx.L2BlockNumber > l2Block.L2BlockNumber {
						break
					}
				}

				fullBatch.L2Blocks = append(fullBatch.L2Blocks, fullBlock)
				prevL2BlockNumber = l2Block.L2BlockNumber
				currentL2Block++
			} else if l2Block.BatchNumber > batch.BatchNumber {
				break
			}
		}

		fullBatches = append(fullBatches, fullBatch)
	}

	return fullBatches
}
*/
