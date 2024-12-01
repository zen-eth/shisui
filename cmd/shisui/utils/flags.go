package utils

import (
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/node"
	"github.com/optimism-java/shisui2/internal/flags"
	"github.com/optimism-java/shisui2/portalwire"
	"github.com/urfave/cli/v2"
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
		Value:    node.DefaultHTTPPort,
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

	PortalUDPListenAddrFlag = &cli.StringFlag{
		Name:     "udp.addr",
		Usage:    "Protocol UDP server listening interface",
		Value:    "",
		Category: flags.PortalNetworkCategory,
	}

	PortalUDPPortFlag = &cli.IntFlag{
		Name:     "udp.port",
		Usage:    "Protocol UDP server listening port",
		Value:    node.DefaultUDPPort,
		Category: flags.PortalNetworkCategory,
	}

	PortalLogLevelFlag = &cli.IntFlag{
		Name:     "loglevel",
		Usage:    "Loglevel of portal network",
		Value:    node.DefaultLoglevel,
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
		Value:    cli.NewStringSlice(portalwire.History.Name()),
	}
)
