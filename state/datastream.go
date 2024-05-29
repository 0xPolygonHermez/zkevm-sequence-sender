package state

import (
	"context"
	"encoding/binary"
	"math/big"

	"github.com/0xPolygonHermez/zkevm-data-streamer/datastreamer"
	"github.com/ethereum/go-ethereum/common"
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
	BatchNumber     uint64         // 8 bytes
	L2BlockNumber   uint64         // 8 bytes
	Timestamp       int64          // 8 bytes
	L1InfoTreeIndex uint32         // 4 bytes
	L1BlockHash     common.Hash    // 32 bytes
	GlobalExitRoot  common.Hash    // 32 bytes
	Coinbase        common.Address // 20 bytes
	ForkID          uint16         // 2 bytes
	ChainID         uint32         // 4 bytes
	BlockHash       common.Hash    // 32 bytes
	StateRoot       common.Hash    // 32 bytes
}

// DSL2BlockStart represents a data stream L2 block start
type DSL2BlockStart struct {
	BatchNumber     uint64         // 8 bytes
	L2BlockNumber   uint64         // 8 bytes
	Timestamp       int64          // 8 bytes
	DeltaTimestamp  uint32         // 4 bytes
	L1InfoTreeIndex uint32         // 4 bytes
	L1BlockHash     common.Hash    // 32 bytes
	GlobalExitRoot  common.Hash    // 32 bytes
	Coinbase        common.Address // 20 bytes
	ForkID          uint16         // 2 bytes
	ChainID         uint32         // 4 bytes

}

// Encode returns the encoded DSL2BlockStart as a byte slice
func (b DSL2BlockStart) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = binary.BigEndian.AppendUint64(bytes, b.BatchNumber)
	bytes = binary.BigEndian.AppendUint64(bytes, b.L2BlockNumber)
	bytes = binary.BigEndian.AppendUint64(bytes, uint64(b.Timestamp))
	bytes = binary.BigEndian.AppendUint32(bytes, b.DeltaTimestamp)
	bytes = binary.BigEndian.AppendUint32(bytes, b.L1InfoTreeIndex)
	bytes = append(bytes, b.L1BlockHash.Bytes()...)
	bytes = append(bytes, b.GlobalExitRoot.Bytes()...)
	bytes = append(bytes, b.Coinbase.Bytes()...)
	bytes = binary.BigEndian.AppendUint16(bytes, b.ForkID)
	bytes = binary.BigEndian.AppendUint32(bytes, b.ChainID)
	return bytes
}

// Decode decodes the DSL2BlockStart from a byte slice
func (b DSL2BlockStart) Decode(data []byte) DSL2BlockStart {
	b.BatchNumber = binary.BigEndian.Uint64(data[0:8])
	b.L2BlockNumber = binary.BigEndian.Uint64(data[8:16])
	b.Timestamp = int64(binary.BigEndian.Uint64(data[16:24]))
	b.DeltaTimestamp = binary.BigEndian.Uint32(data[24:28])
	b.L1InfoTreeIndex = binary.BigEndian.Uint32(data[28:32])
	b.L1BlockHash = common.BytesToHash(data[32:64])
	b.GlobalExitRoot = common.BytesToHash(data[64:96])
	b.Coinbase = common.BytesToAddress(data[96:116])
	b.ForkID = binary.BigEndian.Uint16(data[116:118])
	b.ChainID = binary.BigEndian.Uint32(data[118:122])

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
	bytes = binary.BigEndian.AppendUint32(bytes, l.EncodedLength)
	bytes = append(bytes, l.Encoded...)
	return bytes
}

// Decode decodes the DSL2Transaction from a byte slice
func (l DSL2Transaction) Decode(data []byte) DSL2Transaction {
	l.EffectiveGasPricePercentage = data[0]
	l.IsValid = data[1]
	l.StateRoot = common.BytesToHash(data[2:34])
	l.EncodedLength = binary.BigEndian.Uint32(data[34:38])
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
	bytes = binary.BigEndian.AppendUint64(bytes, b.L2BlockNumber)
	bytes = append(bytes, b.BlockHash[:]...)
	bytes = append(bytes, b.StateRoot[:]...)
	return bytes
}

// Decode decodes the DSL2BlockEnd from a byte slice
func (b DSL2BlockEnd) Decode(data []byte) DSL2BlockEnd {
	b.L2BlockNumber = binary.BigEndian.Uint64(data[0:8])
	b.BlockHash = common.BytesToHash(data[8:40])
	b.StateRoot = common.BytesToHash(data[40:72])
	return b
}

// DSBookMark represents a data stream bookmark
type DSBookMark struct {
	Type  byte   // 1 byte
	Value uint64 // 8 bytes
}

// Encode returns the encoded DSBookMark as a byte slice
func (b DSBookMark) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = append(bytes, b.Type)
	bytes = binary.BigEndian.AppendUint64(bytes, b.Value)
	return bytes
}

// Decode decodes the DSBookMark from a byte slice
func (b DSBookMark) Decode(data []byte) DSBookMark {
	b.Type = data[0]
	b.Value = binary.BigEndian.Uint64(data[1:9])
	return b
}

// DSUpdateGER represents a data stream GER update
type DSUpdateGER struct {
	BatchNumber    uint64         // 8 bytes
	Timestamp      int64          // 8 bytes
	GlobalExitRoot common.Hash    // 32 bytes
	Coinbase       common.Address // 20 bytes
	ForkID         uint16         // 2 bytes
	ChainID        uint32         // 4 bytes
	StateRoot      common.Hash    // 32 bytes
}

// Encode returns the encoded DSUpdateGER as a byte slice
func (g DSUpdateGER) Encode() []byte {
	bytes := make([]byte, 0)
	bytes = binary.BigEndian.AppendUint64(bytes, g.BatchNumber)
	bytes = binary.BigEndian.AppendUint64(bytes, uint64(g.Timestamp))
	bytes = append(bytes, g.GlobalExitRoot[:]...)
	bytes = append(bytes, g.Coinbase[:]...)
	bytes = binary.BigEndian.AppendUint16(bytes, g.ForkID)
	bytes = binary.BigEndian.AppendUint32(bytes, g.ChainID)
	bytes = append(bytes, g.StateRoot[:]...)
	return bytes
}

// Decode decodes the DSUpdateGER from a byte slice
func (g DSUpdateGER) Decode(data []byte) DSUpdateGER {
	g.BatchNumber = binary.BigEndian.Uint64(data[0:8])
	g.Timestamp = int64(binary.BigEndian.Uint64(data[8:16]))
	g.GlobalExitRoot = common.BytesToHash(data[16:48])
	g.Coinbase = common.BytesToAddress(data[48:68])
	g.ForkID = binary.BigEndian.Uint16(data[68:70])
	g.ChainID = binary.BigEndian.Uint32(data[70:74])
	g.StateRoot = common.BytesToHash(data[74:106])
	return g
}

// DSState gathers the methods required to interact with the data stream state.
type DSState interface {
	GetDSGenesisBlock(ctx context.Context, dbTx pgx.Tx) (*DSL2Block, error)
	GetDSBatches(ctx context.Context, firstBatchNumber, lastBatchNumber uint64, readWIPBatch bool, dbTx pgx.Tx) ([]*DSBatch, error)
	GetDSL2Blocks(ctx context.Context, firstBatchNumber, lastBatchNumber uint64, dbTx pgx.Tx) ([]*DSL2Block, error)
	GetDSL2Transactions(ctx context.Context, firstL2Block, lastL2Block uint64, dbTx pgx.Tx) ([]*DSL2Transaction, error)
	GetStorageAt(ctx context.Context, address common.Address, position *big.Int, root common.Hash) (*big.Int, error)
	GetVirtualBatchParentHash(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) (common.Hash, error)
	GetForcedBatchParentHash(ctx context.Context, forcedBatchNumber uint64, dbTx pgx.Tx) (common.Hash, error)
}
