package state

const (
	// FORKID_BLUEBERRY is the fork id 4
	FORKID_BLUEBERRY = 4
	// FORKID_DRAGONFRUIT is the fork id 5
	FORKID_DRAGONFRUIT = 5
	// FORKID_INCABERRY is the fork id 6
	FORKID_INCABERRY = 6
	// FORKID_ETROG is the fork id 7
	FORKID_ETROG = 7
)

// ForkIDInterval is a fork id interval
type ForkIDInterval struct {
	FromBatchNumber uint64
	ToBatchNumber   uint64
	ForkId          uint64
	Version         string
	BlockNumber     uint64
}
