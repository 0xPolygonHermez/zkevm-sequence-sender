package state

// ZKCounters counters for the tx
type ZKCounters struct {
	GasUsed              uint64
	UsedKeccakHashes     uint32
	UsedPoseidonHashes   uint32
	UsedPoseidonPaddings uint32
	UsedMemAligns        uint32
	UsedArithmetics      uint32
	UsedBinaries         uint32
	UsedSteps            uint32
	UsedSha256Hashes_V2  uint32
}

// BatchResources is a struct that contains the ZKEVM resources used by a batch/tx
type BatchResources struct {
	ZKCounters ZKCounters
	Bytes      uint64
}
