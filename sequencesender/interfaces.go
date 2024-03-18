package sequencesender

import (
	"context"

	ethmanTypes "github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type ethermaner interface {
	CurrentNonce(ctx context.Context, account common.Address) (uint64, error)
	EstimateGasSequenceBatches(sender common.Address, sequences []ethmanTypes.Sequence, maxSequenceTimestamp uint64, initSequenceBatchNumber uint64, l2Coinbase common.Address) (*types.Transaction, error)
	BuildSequenceBatchesTxData(sender common.Address, sequences []ethmanTypes.Sequence, maxSequenceTimestamp uint64, lastSequencedBatchNumber uint64, l2Coinbase common.Address) (to *common.Address, data []byte, err error)
	BuildSequenceBatchesTxBlob(sender common.Address, sequences []ethmanTypes.Sequence, maxSequenceTimestamp uint64, lastSequencedBatchNumber uint64, l2Coinbase common.Address) (to *common.Address, data []byte, sidecar *types.BlobTxSidecar, err error)
	GetLatestBatchNumber() (uint64, error)
	SendTx(ctx context.Context, tx *types.Transaction) error
	LoadAuthFromKeyStore(path, password string) (*bind.TransactOpts, error)
	NewAuthFromKeystore(path, password string, chainID uint64) (bind.TransactOpts, error)
}
