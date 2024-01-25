package sequencesender

import (
	"context"

	ethmanTypes "github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// etherman contains the methods required to interact with ethereum.
type etherman interface {
	BuildSequenceBatchesTxData(sender common.Address, sequences []ethmanTypes.Sequence, l2Coinbase common.Address) (to *common.Address, data []byte, err error)
	EstimateGasSequenceBatches(sender common.Address, sequences []ethmanTypes.Sequence, l2Coinbase common.Address) (*types.Transaction, error)
	// GetLastBatchTimestamp() (uint64, error)
	GetLatestBlockTimestamp(ctx context.Context) (uint64, error)
	GetLatestBatchNumber() (uint64, error)
}
