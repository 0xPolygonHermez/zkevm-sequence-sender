package etherman

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/smartcontracts/polygonrollupmanager"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/smartcontracts/polygonzkevm"
	ethmanTypes "github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ethereumClient interface {
	ethereum.ChainReader
	ethereum.ChainStateReader
	ethereum.ContractCaller
	ethereum.GasEstimator
	ethereum.GasPricer
	ethereum.GasPricer1559
	ethereum.LogFilterer
	ethereum.TransactionReader
	ethereum.TransactionSender

	bind.DeployBackend
}

// L1Config represents the configuration of the network used in L1
type L1Config struct {
	// Chain ID of the L1 network
	L1ChainID uint64 `json:"chainId"`
	// ZkEVMAddr Address of the L1 contract polygonZkEVMAddress
	ZkEVMAddr common.Address `json:"polygonZkEVMAddress"`
	// RollupManagerAddr Address of the L1 contract
	RollupManagerAddr common.Address `json:"polygonRollupManagerAddress"`
	// PolAddr Address of the L1 Pol token Contract
	PolAddr common.Address `json:"polTokenAddress"`
	// GlobalExitRootManagerAddr Address of the L1 GlobalExitRootManager contract
	GlobalExitRootManagerAddr common.Address `json:"polygonZkEVMGlobalExitRootAddress"`
}

// Client is a simple implementation of EtherMan.
type Client struct {
	EthClient     ethereumClient
	ZkEVM         *polygonzkevm.Polygonzkevm
	RollupManager *polygonrollupmanager.Polygonrollupmanager

	RollupID uint32

	l1Cfg L1Config
	cfg   Config
	auth  map[common.Address]bind.TransactOpts // empty in case of read-only client
}

// NewClient creates a new etherman.
func NewClient(cfg Config, l1Config L1Config) (*Client, error) {
	// Connect to ethereum node
	ethClient, err := ethclient.Dial(cfg.EthermanConfig.URL)
	if err != nil {
		log.Errorf("error connecting to %s: %+v", cfg.EthermanConfig.URL, err)
		return nil, err
	}
	// Create smc clients
	zkevm, err := polygonzkevm.NewPolygonzkevm(l1Config.ZkEVMAddr, ethClient)
	if err != nil {
		return nil, err
	}
	rollupManager, err := polygonrollupmanager.NewPolygonrollupmanager(l1Config.RollupManagerAddr, ethClient)
	if err != nil {
		return nil, err
	}

	// Get RollupID
	rollupID, err := rollupManager.RollupAddressToID(&bind.CallOpts{Pending: false}, l1Config.ZkEVMAddr)
	if err != nil {
		return nil, err
	}
	log.Debug("rollupID: ", rollupID)

	return &Client{
		EthClient:     ethClient,
		ZkEVM:         zkevm,
		RollupManager: rollupManager,
		RollupID:      rollupID,
		l1Cfg:         l1Config,
		cfg:           cfg,
		auth:          map[common.Address]bind.TransactOpts{},
	}, nil
}

// EstimateGasSequenceBatches estimates gas for sending batches
func (etherMan *Client) EstimateGasSequenceBatches(sender common.Address, sequences []ethmanTypes.Sequence, maxSequenceTimestamp uint64, initSequenceBatchNumber uint64, l2Coinbase common.Address) (*types.Transaction, error) {
	opts, err := etherMan.getAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, ErrPrivateKeyNotFound
	}
	opts.NoSend = true

	// Cost using calldata
	tx, err := etherMan.sequenceBatches(opts, sequences, maxSequenceTimestamp, initSequenceBatchNumber, l2Coinbase)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// BuildSequenceBatchesTxData builds a []bytes to be sent to the PoE SC method SequenceBatches.
func (etherMan *Client) BuildSequenceBatchesTxData(sender common.Address, sequences []ethmanTypes.Sequence, maxSequenceTimestamp uint64, lastSequencedBatchNumber uint64, l2Coinbase common.Address) (to *common.Address, data []byte, err error) {
	opts, err := etherMan.getAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, nil, fmt.Errorf("failed to build sequence batches, err: %w", ErrPrivateKeyNotFound)
	}
	opts.NoSend = true
	// force nonce, gas limit and gas price to avoid querying it from the chain
	opts.Nonce = big.NewInt(1)
	opts.GasLimit = uint64(1)
	opts.GasPrice = big.NewInt(1)

	var tx *types.Transaction
	tx, err = etherMan.sequenceBatches(opts, sequences, maxSequenceTimestamp, lastSequencedBatchNumber, l2Coinbase)
	if err != nil {
		return nil, nil, err
	}

	return tx.To(), tx.Data(), nil
}

// GetLatestBatchNumber function allows to retrieve the latest proposed batch in the smc
func (etherMan *Client) GetLatestBatchNumber() (uint64, error) {
	rollupData, err := etherMan.RollupManager.RollupIDToRollupData(&bind.CallOpts{Pending: false}, etherMan.RollupID)
	if err != nil {
		return 0, err
	}
	return rollupData.LastBatchSequenced, nil
}

// CurrentNonce returns the current nonce for the provided account
func (etherMan *Client) CurrentNonce(ctx context.Context, account common.Address) (uint64, error) {
	return etherMan.EthClient.NonceAt(ctx, account, nil)
}

// LoadAuthFromKeyStore loads an authorization from a key store file
func (etherMan *Client) LoadAuthFromKeyStore(path, password string) (*bind.TransactOpts, error) {
	auth, err := newAuthFromKeystore(path, password, etherMan.l1Cfg.L1ChainID)
	if err != nil {
		return nil, err
	}

	log.Infof("loaded authorization for address: %v", auth.From.String())
	etherMan.auth[auth.From] = auth
	return &auth, nil
}

// getAuthByAddress tries to get an authorization from the authorizations map
func (etherMan *Client) getAuthByAddress(addr common.Address) (bind.TransactOpts, error) {
	auth, found := etherMan.auth[addr]
	if !found {
		return bind.TransactOpts{}, ErrNotFound
	}
	return auth, nil
}

func (etherMan *Client) sequenceBatches(opts bind.TransactOpts, sequences []ethmanTypes.Sequence, maxSequenceTimestamp uint64, lastSequencedBatchNumber uint64, l2Coinbase common.Address) (*types.Transaction, error) {
	var batches []polygonzkevm.PolygonRollupBaseEtrogBatchData
	for _, seq := range sequences {
		var ger common.Hash
		if seq.ForcedBatchTimestamp > 0 {
			ger = seq.GlobalExitRoot
		}
		batch := polygonzkevm.PolygonRollupBaseEtrogBatchData{
			Transactions:         seq.BatchL2Data,
			ForcedGlobalExitRoot: ger,
			ForcedTimestamp:      uint64(seq.ForcedBatchTimestamp),
			ForcedBlockHashL1:    seq.PrevBlockHash,
		}

		batches = append(batches, batch)
	}

	tx, err := etherMan.ZkEVM.SequenceBatches(&opts, batches, maxSequenceTimestamp, lastSequencedBatchNumber, l2Coinbase)
	if err != nil {
		log.Debugf("Batches to send: %+v", batches)
		log.Debug("l2CoinBase: ", l2Coinbase)
		log.Debug("Sequencer address: ", opts.From)
		a, err2 := polygonzkevm.PolygonzkevmMetaData.GetAbi()
		if err2 != nil {
			log.Error("error getting abi. Error: ", err2)
		}
		input, err3 := a.Pack("sequenceBatches", batches, maxSequenceTimestamp, lastSequencedBatchNumber, l2Coinbase)
		if err3 != nil {
			log.Error("error packing call. Error: ", err3)
		}
		ctx := context.Background()
		var b string
		block, err4 := etherMan.EthClient.BlockByNumber(ctx, nil)
		if err4 != nil {
			log.Error("error getting blockNumber. Error: ", err4)
			b = "latest"
		} else {
			b = fmt.Sprintf("%x", block.Number())
		}
		log.Warnf(`Use the next command to debug it manually.
		curl --location --request POST 'http://localhost:8545' \
		--header 'Content-Type: application/json' \
		--data-raw '{
			"jsonrpc": "2.0",
			"method": "eth_call",
			"params": [{"from": "%s","to":"%s","data":"0x%s"},"0x%s"],
			"id": 1
		}'`, opts.From, etherMan.l1Cfg.ZkEVMAddr, common.Bytes2Hex(input), b)
		if parsedErr, ok := tryParseError(err); ok {
			err = parsedErr
		}
	}

	return tx, err
}

// AddOrReplaceAuth adds an authorization or replace an existent one to the same account
func (etherMan *Client) AddOrReplaceAuth(auth bind.TransactOpts) error {
	log.Infof("added or replaced authorization for address: %v", auth.From.String())
	etherMan.auth[auth.From] = auth
	return nil
}

// newAuthFromKeystore an authorization instance from a keystore file
func newAuthFromKeystore(path, password string, chainID uint64) (bind.TransactOpts, error) {
	log.Infof("reading key from: %v", path)
	key, err := newKeyFromKeystore(path, password)
	if err != nil {
		return bind.TransactOpts{}, err
	}
	if key == nil {
		return bind.TransactOpts{}, nil
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, new(big.Int).SetUint64(chainID))
	if err != nil {
		return bind.TransactOpts{}, err
	}
	return *auth, nil
}

// newKeyFromKeystore creates an instance of a keystore key from a keystore file
func newKeyFromKeystore(path, password string) (*keystore.Key, error) {
	if path == "" && password == "" {
		return nil, nil
	}
	keystoreEncrypted, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	log.Infof("decrypting key from: %v", path)
	key, err := keystore.DecryptKey(keystoreEncrypted, password)
	if err != nil {
		return nil, err
	}
	return key, nil
}
