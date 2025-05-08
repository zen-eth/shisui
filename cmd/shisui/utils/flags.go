package utils

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/metrics/exp"
	"github.com/ethereum/go-ethereum/metrics/influxdb"
	"github.com/urfave/cli/v2"
	"github.com/zen-eth/shisui/internal/flags"
	"github.com/zen-eth/shisui/portal"
	"github.com/zen-eth/shisui/portalwire"
)

var (
	// Metrics flags
	MetricsEnabledFlag = &cli.BoolFlag{
		Name:     "metrics",
		Usage:    "Enable metrics collection and reporting",
		Category: flags.MetricsCategory,
	}
	// MetricsHTTPFlag defines the endpoint for a stand-alone metrics HTTP endpoint.
	// Since the pprof service enables sensitive/vulnerable behavior, this allows a user
	// to enable a public-OK metrics endpoint without having to worry about ALSO exposing
	// other profiling behavior or information.
	MetricsHTTPFlag = &cli.StringFlag{
		Name:     "metrics.addr",
		Usage:    `Enable stand-alone metrics HTTP server listening interface.`,
		Category: flags.MetricsCategory,
	}
	MetricsPortFlag = &cli.IntFlag{
		Name: "metrics.port",
		Usage: `Metrics HTTP server listening port.
Please note that --` + MetricsHTTPFlag.Name + ` must be set to start the server.`,
		Value:    metrics.DefaultConfig.Port,
		Category: flags.MetricsCategory,
	}
	MetricsEnableInfluxDBFlag = &cli.BoolFlag{
		Name:     "metrics.influxdb",
		Usage:    "Enable metrics export/push to an external InfluxDB database",
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBEndpointFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.endpoint",
		Usage:    "InfluxDB API endpoint to report metrics to",
		Value:    metrics.DefaultConfig.InfluxDBEndpoint,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBDatabaseFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.database",
		Usage:    "InfluxDB database name to push reported metrics to",
		Value:    metrics.DefaultConfig.InfluxDBDatabase,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBUsernameFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.username",
		Usage:    "Username to authorize access to the database",
		Value:    metrics.DefaultConfig.InfluxDBUsername,
		Category: flags.MetricsCategory,
	}
	MetricsInfluxDBPasswordFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.password",
		Usage:    "Password to authorize access to the database",
		Value:    metrics.DefaultConfig.InfluxDBPassword,
		Category: flags.MetricsCategory,
	}
	// Tags are part of every measurement sent to InfluxDB. Queries on tags are faster in InfluxDB.
	// For example `host` tag could be used so that we can group all nodes and average a measurement
	// across all of them, but also so that we can select a specific node and inspect its measurements.
	// https://docs.influxdata.com/influxdb/v1.4/concepts/key_concepts/#tag-key
	MetricsInfluxDBTagsFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.tags",
		Usage:    "Comma-separated InfluxDB tags (key/values) attached to all measurements",
		Value:    metrics.DefaultConfig.InfluxDBTags,
		Category: flags.MetricsCategory,
	}

	MetricsEnableInfluxDBV2Flag = &cli.BoolFlag{
		Name:     "metrics.influxdbv2",
		Usage:    "Enable metrics export/push to an external InfluxDB v2 database",
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBTokenFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.token",
		Usage:    "Token to authorize access to the database (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBToken,
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBBucketFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.bucket",
		Usage:    "InfluxDB bucket name to push reported metrics to (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBBucket,
		Category: flags.MetricsCategory,
	}

	MetricsInfluxDBOrganizationFlag = &cli.StringFlag{
		Name:     "metrics.influxdb.organization",
		Usage:    "InfluxDB organization name (v2 only)",
		Value:    metrics.DefaultConfig.InfluxDBOrganization,
		Category: flags.MetricsCategory,
	}

	PortalRPCListenAddrFlag = &cli.StringFlag{
		Name:     "rpc.addr",
		Usage:    "HTTP-RPC server listening interface",
		Category: flags.PortalNetworkCategory,
	}

	PortalRPCPortFlag = &cli.IntFlag{
		Name:     "rpc.port",
		Usage:    "HTTP-RPC server listening port",
		Value:    8545,
		Category: flags.PortalNetworkCategory,
	}

	PortalDataDirFlag = &cli.StringFlag{
		Name:     "data.dir",
		Usage:    "Data dir of where the data file located",
		Value:    "./",
		Category: flags.PortalNetworkCategory,
	}

	PortalDataCapacityFlag = &cli.Uint64Flag{
		Name:     "data.capacity",
		Usage:    "The capacity of the data stored, the unit is MB",
		Value:    1000 * 10, // 10 GB
		Category: flags.PortalNetworkCategory,
	}

	PortalNATFlag = &cli.StringFlag{
		Name:     "nat",
		Usage:    "NAT port mapping mechanism (any|none|upnp|pmp|stun|pmp:<IP>|extip:<IP>|stun:<IP>)",
		Value:    "any",
		Category: flags.PortalNetworkCategory,
	}

	PortalUDPPortFlag = &cli.IntFlag{
		Name:     "udp.port",
		Usage:    "PortalProtocolConfig UDP server listening port",
		Value:    9009,
		Category: flags.PortalNetworkCategory,
	}

	PortalLogLevelFlag = &cli.IntFlag{
		Name:     "loglevel",
		Usage:    "Loglevel of portal network",
		Value:    3,
		Category: flags.PortalNetworkCategory,
	}

	PortalLogFormatFlag = &cli.StringFlag{
		Name:     "logformat",
		Usage:    "Log format to use (json|logfmt|terminal)",
		Category: flags.PortalNetworkCategory,
	}

	PortalPrivateKeyFlag = &cli.StringFlag{
		Name:     "private.key",
		Usage:    "Private key of p2p node, hex format without 0x prifix",
		Category: flags.PortalNetworkCategory,
	}

	PortalBootNodesFlag = &cli.StringFlag{
		Name:     "bootnodes",
		Usage:    "Comma separated enode URLs for P2P discovery bootstrap",
		Category: flags.PortalNetworkCategory,
	}

	PortalNetworksFlag = &cli.StringSliceFlag{
		Name:     "networks",
		Usage:    "Portal sub networks: history, beacon, state",
		Category: flags.PortalNetworkCategory,
		Value:    cli.NewStringSlice(portalwire.History.Name(), portalwire.Beacon.Name()),
	}
	PortalDiscv5GnetFlag = &cli.BoolFlag{
		Name:     "discv5.gnet",
		Usage:    "Enable gnet on discv5, default is go udp connection",
		Category: flags.PortalNetworkCategory,
		Value:    false,
	}
	PortalTrustedBlockRootFlag = &cli.StringFlag{
		Name:     "trusted-block-root",
		Usage:    "Hex encoded block root from a trusted checkpoint",
		Category: flags.PortalNetworkCategory,
	}
	PortalTableInitFlag = &cli.BoolFlag{
		Name:     "disable-init-check",
		Usage:    "Disable init check in table, for hive test",
		Category: flags.PortalNetworkCategory,
		Value:    false,
	}

	PortalUtpConnSizeLimitFlag = &cli.IntFlag{
		Name:     "utp-conn-size-limit",
		Usage:    "Limit the number of UTP connections, with a default value of 50",
		Value:    portalwire.DefaultUtpConnSize,
		Category: flags.PortalNetworkCategory,
	}
	PortalExternalOracleFlag = &cli.StringFlag{
		Name:     "external.oracle",
		Usage:    "External oracle for knowing the HEAD of the history chain",
		Category: flags.PortalNetworkCategory,
	}
)

// verify availability of external oracle for history
func VerifyExternalOracle(config *portal.Config) {
	if slices.Contains(config.Networks, portalwire.History.Name()) {
		if !slices.Contains(config.Networks, portalwire.Beacon.Name()) && len(config.ExternalOracle) <= 0 {
			Fatalf("History sub network requires either the beacon network or an external oracle to be provided")
		}
	}
}

func SetupMetrics(cfg *metrics.Config) {
	if !cfg.Enabled {
		return
	}
	log.Info("Enabling metrics collection")
	metrics.Enable()

	// InfluxDB exporter.
	var (
		enableExport   = cfg.EnableInfluxDB
		enableExportV2 = cfg.EnableInfluxDBV2
	)
	if cfg.EnableInfluxDB && cfg.EnableInfluxDBV2 {
		Fatalf("Flags %v can't be used at the same time", strings.Join([]string{MetricsEnableInfluxDBFlag.Name, MetricsEnableInfluxDBV2Flag.Name}, ", "))
	}
	var (
		endpoint = cfg.InfluxDBEndpoint
		database = cfg.InfluxDBDatabase
		username = cfg.InfluxDBUsername
		password = cfg.InfluxDBPassword

		token        = cfg.InfluxDBToken
		bucket       = cfg.InfluxDBBucket
		organization = cfg.InfluxDBOrganization
		tagsMap      = SplitTagsFlag(cfg.InfluxDBTags)
	)
	if enableExport {
		log.Info("Enabling metrics export to InfluxDB")
		go influxdb.InfluxDBWithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, database, username, password, "geth.", tagsMap)
	} else if enableExportV2 {
		tagsMap := SplitTagsFlag(cfg.InfluxDBTags)
		log.Info("Enabling metrics export to InfluxDB (v2)")
		go influxdb.InfluxDBV2WithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, token, bucket, organization, "geth.", tagsMap)
	}

	// Expvar exporter.
	if cfg.HTTP != "" {
		address := net.JoinHostPort(cfg.HTTP, fmt.Sprintf("%d", cfg.Port))
		log.Info("Enabling stand-alone metrics HTTP endpoint", "address", address)
		exp.Setup(address)
	} else if cfg.HTTP == "" && cfg.Port != 0 {
		log.Warn(fmt.Sprintf("--%s specified without --%s, metrics server will not start.", MetricsPortFlag.Name, MetricsHTTPFlag.Name))
	}

	// Enable system metrics collection.
	go metrics.CollectProcessMetrics(3 * time.Second)
}

// CheckExclusive verifies that only a single instance of the provided flags was
// set by the user. Each flag might optionally be followed by a string type to
// specialize it further.
func CheckExclusive(ctx *cli.Context, args ...interface{}) {
	set := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		// Make sure the next argument is a flag and skip if not set
		flag, ok := args[i].(cli.Flag)
		if !ok {
			panic(fmt.Sprintf("invalid argument, not cli.Flag type: %T", args[i]))
		}
		// Check if next arg extends current and expand its name if so
		name := flag.Names()[0]

		if i+1 < len(args) {
			switch option := args[i+1].(type) {
			case string:
				// Extended flag check, make sure value set doesn't conflict with passed in option
				if ctx.String(flag.Names()[0]) == option {
					name += "=" + option
					set = append(set, "--"+name)
				}
				// shift arguments and continue
				i++
				continue

			case cli.Flag:
			default:
				panic(fmt.Sprintf("invalid argument, not cli.Flag or string extension: %T", args[i+1]))
			}
		}
		// Mark the flag if it's set
		if ctx.IsSet(flag.Names()[0]) {
			set = append(set, "--"+name)
		}
	}
	if len(set) > 1 {
		Fatalf("Flags %v can't be used at the same time", strings.Join(set, ", "))
	}
}

// Fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func Fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

func SplitTagsFlag(tagsFlag string) map[string]string {
	tags := strings.Split(tagsFlag, ",")
	tagsMap := map[string]string{}

	for _, t := range tags {
		if t != "" {
			kv := strings.Split(t, "=")

			if len(kv) == 2 {
				tagsMap[kv[0]] = kv[1]
			}
		}
	}

	return tagsMap
}

// SplitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func SplitAndTrim(input string) (ret []string) {
	l := strings.Split(input, ",")
	for _, r := range l {
		if r = strings.TrimSpace(r); r != "" {
			ret = append(ret, r)
		}
	}
	return ret
}
