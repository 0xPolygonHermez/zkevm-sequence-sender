package sequencesender

import (
	"context"

	ethmanTypes "github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type ethermaner interface {
	CurrentNonce(ctx context.Context, account common.Address) (uint64, error)
	BuildSequenceBatchesTx(sender common.Address, sequences []ethmanTypes.Sequence, maxSequenceTimestamp uint64, lastSequencedBatchNumber uint64, l2Coinbase common.Address, dataAvailabilityMessage []byte) (*types.Transaction, error)
	GetLatestBatchNumber() (uint64, error)
}

type dataAvailabilityLayer interface {
	PostSequence(ctx context.Context, sequences []ethmanTypes.Sequence) ([]byte, error)
}
