package state

import (
	"encoding/binary"

	"github.com/0xPolygonHermez/zkevm-data-streamer/datastreamer"
	"github.com/ethereum/go-ethereum/common"
)

const (

	// EntryTypeL2BlockStart represents a L2 block start
	EntryTypeL2BlockStart datastreamer.EntryType = 1
	// BookMarkTypeBatch represents a batch
	BookMarkTypeBatch byte = 1
	// EntryTypeL2Tx represents a L2 transaction
	EntryTypeL2Tx datastreamer.EntryType = 2
	// EntryTypeL2BlockEnd represents a L2 block end
	EntryTypeL2BlockEnd datastreamer.EntryType = 3
)

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
	LocalExitRoot   common.Hash    // 32 bytes
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
	bytes = append(bytes, b.LocalExitRoot.Bytes()...)
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
	b.LocalExitRoot = common.BytesToHash(data[122:154])
	return b
}

// DSL2Transaction represents a data stream L2 transaction
type DSL2Transaction struct {
	L2BlockNumber               uint64      // Not included in the encoded data
	ImStateRoot                 common.Hash // Not included in the encoded data
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
