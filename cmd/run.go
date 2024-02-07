package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/0xPolygonHermez/zkevm-sequence-sender"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/config"
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
	setupLog(c.Log)

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

func setupLog(c log.Config) {
	log.Init(c)
}

func newEtherman(c config.Config) (*etherman.Client, error) {
	return etherman.NewClient(c.Etherman, c.NetworkConfig.L1Config)
}

func createSequenceSender(cfg config.Config) *sequencesender.SequenceSender {
	etherman, err := newEtherman(cfg)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := etherman.LoadAuthFromKeyStore(cfg.SequenceSender.PrivateKey.Path, cfg.SequenceSender.PrivateKey.Password)
	if err != nil {
		log.Fatal(err)
	}
	cfg.SequenceSender.SenderAddress = auth.From

	seqSender, err := sequencesender.New(cfg.SequenceSender, etherman)
	if err != nil {
		log.Fatal(err)
	}

	return seqSender
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
