package main

import (
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/mattn/go-isatty"
	_ "github.com/mattn/go-sqlite3"
	"github.com/urfave/cli/v2"
	"github.com/zen-eth/shisui/cmd/shisui/utils"
	"github.com/zen-eth/shisui/internal/debug"
	"github.com/zen-eth/shisui/internal/flags"
	"github.com/zen-eth/shisui/portal"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	storageCapacity *metrics.Gauge
)

const (
	privateKeyFileName = "clientKey"
)

var app = flags.NewApp("the go-portal-network command line interface")

var (
	portalProtocolFlags = []cli.Flag{
		utils.PortalNATFlag,
		utils.PortalUDPPortFlag,
		utils.PortalBootNodesFlag,
		utils.PortalPrivateKeyFlag,
		utils.PortalNetworksFlag,
		utils.PortalDiscv5GnetFlag,
		utils.PortalTrustedBlockRootFlag,
		utils.PortalTableInitFlag,
		utils.PortalUtpConnSizeLimitFlag,
	}
	historyRpcFlags = []cli.Flag{
		utils.PortalRPCListenAddrFlag,
		utils.PortalRPCPortFlag,
		utils.PortalDataDirFlag,
		utils.PortalDataCapacityFlag,
		utils.PortalLogLevelFlag,
		utils.PortalLogFormatFlag,
	}
	metricsFlags = []cli.Flag{
		utils.MetricsEnabledFlag,
		utils.MetricsHTTPFlag,
		utils.MetricsPortFlag,
		utils.MetricsEnableInfluxDBFlag,
		utils.MetricsInfluxDBEndpointFlag,
		utils.MetricsInfluxDBDatabaseFlag,
		utils.MetricsInfluxDBUsernameFlag,
		utils.MetricsInfluxDBPasswordFlag,
		utils.MetricsInfluxDBTagsFlag,
		utils.MetricsEnableInfluxDBV2Flag,
		utils.MetricsInfluxDBTokenFlag,
		utils.MetricsInfluxDBBucketFlag,
		utils.MetricsInfluxDBOrganizationFlag,
	}
)

func init() {
	app.Action = shisui
	app.Flags = slices.Concat(portalProtocolFlags, historyRpcFlags, metricsFlags, debug.Flags)
	flags.AutoEnvVars(app.Flags, "SHISUI")

	app.Before = func(ctx *cli.Context) error {
		_, err := maxprocs.Set() // Automatically set GOMAXPROCS to match Linux container CPU quota.
		if err != nil {
			return err
		}
		flags.MigrateGlobalFlags(ctx)
		if err := debug.Setup(ctx); err != nil {
			return err
		}
		flags.CheckEnvVars(ctx, app.Flags, "SHISUI")
		return nil
	}

	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		_, err = fmt.Fprintln(os.Stderr, err)
		if err != nil {
			log.Error("Failed to write error to stderr", "err", err)
		}
		os.Exit(1)
	}
}

func shisui(ctx *cli.Context) error {
	err := setDefaultLogger(ctx.Int(utils.PortalLogLevelFlag.Name), ctx.String(utils.PortalLogFormatFlag.Name))
	if err != nil {
		return err
	}

	config, err := getPortalConfig(ctx)
	if err != nil {
		return err
	}

	// Start metrics export if enabled
	utils.SetupMetrics(config.Metrics)

	node, err := portal.NewNode(config)
	if err != nil {
		return err
	}

	if err = node.Start(); err != nil {
		return err
	}

	go handleInterrupt(node)

	node.Wait()

	return nil
}

func setDefaultLogger(logLevel int, logFormat string) error {
	var glogger *log.GlogHandler
	switch logFormat {
	case "json":
		glogger = log.NewGlogHandler(log.JSONHandler(os.Stderr))
	case "logfmt":
		glogger = log.NewGlogHandler(log.LogfmtHandler(os.Stderr))
	case "", "terminal":
		useColor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
		glogger = log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, useColor))
	default:
		// Unknown log format specified
		return fmt.Errorf("unknown log format: %v", logFormat)
	}
	slogVerbosity := log.FromLegacyLevel(logLevel)
	glogger.Verbosity(slogVerbosity)
	defaultLogger := log.NewLogger(glogger)
	log.SetDefault(defaultLogger)

	return nil
}

func handleInterrupt(node *portal.Node) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)

	<-interrupt
	log.Warn("Closing Shisui gracefully")

	// Gracefully shutdown the node
	go node.Stop()

	<-interrupt
	os.Exit(1)
}
