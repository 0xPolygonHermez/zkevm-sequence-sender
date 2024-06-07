package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	dataCommitteeClient "github.com/0xPolygon/cdk-data-availability/client"
	ethtxman "github.com/0xPolygonHermez/zkevm-ethtx-manager/etherman"
	"github.com/0xPolygonHermez/zkevm-ethtx-manager/etherman/etherscan"
	"github.com/0xPolygonHermez/zkevm-sequence-sender"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/config"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/dataavailability"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/dataavailability/datacommittee"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/sequencesender"
	"github.com/urfave/cli/v2"
)

func start(cliCtx *cli.Context) error {
	c, err := config.Load(cliCtx, true)
	if err != nil {
		return err
	}

	log.Init(c.Log)

	if c.Log.Environment == log.EnvironmentDevelopment {
		zkevm.PrintVersion(os.Stdout)
		log.Info("Starting application")
	} else if c.Log.Environment == log.EnvironmentProduction {
		logVersion()
	}

	c.SequenceSender.Log = c.Log
	seqSender := createSequenceSender(*c)
	go seqSender.Start(cliCtx.Context)
	waitSignal(nil)

	return nil
}

func createSequenceSender(cfg config.Config) *sequencesender.SequenceSender {
	ethman, err := etherman.NewClient(etherman.Config{
		EthermanConfig: ethtxman.Config{
			URL:              cfg.SequenceSender.EthTxManager.Etherman.URL,
			MultiGasProvider: cfg.SequenceSender.EthTxManager.Etherman.MultiGasProvider,
			L1ChainID:        cfg.SequenceSender.EthTxManager.Etherman.L1ChainID,
			Etherscan: etherscan.Config{
				ApiKey: cfg.SequenceSender.EthTxManager.Etherman.Etherscan.ApiKey,
				Url:    cfg.SequenceSender.EthTxManager.Etherman.Etherscan.Url,
			},
			HTTPHeaders: cfg.SequenceSender.EthTxManager.Etherman.HTTPHeaders,
		},
		IsValidiumMode: cfg.SequenceSender.IsValidiumMode,
	}, cfg.NetworkConfig.L1Config)
	if err != nil {
		log.Fatal(err)
	}

	auth, _, err := ethman.LoadAuthFromKeyStore(cfg.SequenceSender.PrivateKey.Path, cfg.SequenceSender.PrivateKey.Password)
	if err != nil {
		log.Fatal(err)
	}
	cfg.SequenceSender.SenderAddress = auth.From

	da, err := newDataAvailability(cfg, ethman)
	if err != nil {
		log.Fatal(err)
	}

	seqSender, err := sequencesender.New(cfg.SequenceSender, ethman, da)
	if err != nil {
		log.Fatal(err)
	}

	return seqSender
}

func newDataAvailability(c config.Config, etherman *etherman.Client) (*dataavailability.DataAvailability, error) {
	if !c.SequenceSender.IsValidiumMode {
		return nil, nil
	}

	// Backend specific config
	daProtocolName, err := etherman.GetDAProtocolName()
	if err != nil {
		return nil, fmt.Errorf("error getting data availability protocol name: %v", err)
	}
	var daBackend dataavailability.DABackender
	switch daProtocolName {
	case string(dataavailability.DataAvailabilityCommittee):
		var (
			pk  *ecdsa.PrivateKey
			err error
		)
		_, pk, err = etherman.LoadAuthFromKeyStore(c.SequenceSender.PrivateKey.Path, c.SequenceSender.PrivateKey.Password)
		if err != nil {
			return nil, err
		}
		dacAddr, err := etherman.GetDAProtocolAddr()
		if err != nil {
			return nil, fmt.Errorf("error getting trusted sequencer URI. Error: %v", err)
		}

		daBackend, err = datacommittee.New(
			c.SequenceSender.EthTxManager.Etherman.URL,
			dacAddr,
			pk,
			dataCommitteeClient.NewFactory(),
		)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected / unsupported DA protocol: %s", daProtocolName)
	}

	return dataavailability.New(daBackend)
}

func logVersion() {
	log.Infow("Starting application",
		// node version is already logged by default
		"gitRevision", zkevm.GitRev,
		"gitBranch", zkevm.GitBranch,
		"goVersion", runtime.Version(),
		"built", zkevm.BuildDate,
		"os/arch", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	)
}

func waitSignal(cancelFuncs []context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	for sig := range signals {
		switch sig {
		case os.Interrupt, os.Kill:
			log.Info("terminating application gracefully...")

			exitStatus := 0
			for _, cancel := range cancelFuncs {
				cancel()
			}
			os.Exit(exitStatus)
		}
	}
}
