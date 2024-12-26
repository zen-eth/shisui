package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/urfave/cli/v2"
	"github.com/zen-eth/shisui/cmd/shisui/utils"
	"github.com/zen-eth/shisui/portalwire"
)

func getPortalConfig(ctx *cli.Context) (*Config, error) {
	config := &Config{
		Protocol: portalwire.DefaultPortalProtocolConfig(),
		Metrics:  &metrics.DefaultConfig,
	}

	httpAddr := ctx.String(utils.PortalRPCListenAddrFlag.Name)
	httpPort := ctx.String(utils.PortalRPCPortFlag.Name)
	config.RpcAddr = net.JoinHostPort(httpAddr, httpPort)
	config.DataDir = ctx.String(utils.PortalDataDirFlag.Name)
	config.DataCapacity = ctx.Uint64(utils.PortalDataCapacityFlag.Name)
	config.LogLevel = ctx.Int(utils.PortalLogLevelFlag.Name)
	port := ctx.String(utils.PortalUDPPortFlag.Name)
	if !strings.HasPrefix(port, ":") {
		config.Protocol.ListenAddr = ":" + port
	} else {
		config.Protocol.ListenAddr = port
	}

	err := setPrivateKey(ctx, config)
	if err != nil {
		return config, err
	}

	natString := ctx.String(utils.PortalNATFlag.Name)
	if natString != "" {
		natInterface, err := nat.Parse(natString)
		if err != nil {
			return config, err
		}
		config.Protocol.NAT = natInterface
	}

	setPortalBootstrapNodes(ctx, config)
	config.Networks = ctx.StringSlice(utils.PortalNetworksFlag.Name)

	applyMetricConfig(ctx, config)
	return config, nil
}

func setPrivateKey(ctx *cli.Context, config *Config) error {
	var privateKey *ecdsa.PrivateKey
	var err error
	keyStr := ctx.String(utils.PortalPrivateKeyFlag.Name)
	if keyStr != "" {
		keyBytes, err := hexutil.Decode(keyStr)
		if err != nil {
			return err
		}
		privateKey, err = crypto.ToECDSA(keyBytes)
		if err != nil {
			return err
		}
	} else {
		fullPath := filepath.Join(config.DataDir, privateKeyFileName)
		if _, err := os.Stat(fullPath); err == nil {
			log.Info("Loading private key from file", "datadir", config.DataDir, "file", privateKeyFileName)
			privateKey, err = readPrivateKey(config, privateKeyFileName)
			if err != nil {
				return err
			}
		} else {
			if os.IsNotExist(err) {
				err := os.MkdirAll(config.DataDir, os.ModePerm)
				if err != nil {
					log.Error("Failed to create directory:", "err", err)
				}
				file, err := os.Create(fullPath)
				if err != nil {
					log.Error("Failed to create file:", "err", err)
				}
				defer func(file *os.File) {
					err := file.Close()
					if err != nil {
						log.Error("Failed to close file:", "err", err)
					}
				}(file)
			}
			log.Info("Creating new private key")
			privateKey, err = crypto.GenerateKey()
			if err != nil {
				return err
			}
		}
	}

	config.PrivateKey = privateKey
	err = writePrivateKey(privateKey, config, privateKeyFileName)
	if err != nil {
		return err
	}
	return nil
}

func writePrivateKey(privateKey *ecdsa.PrivateKey, config *Config, fileName string) error {
	keyEnc := hex.EncodeToString(crypto.FromECDSA(privateKey))

	fullPath := filepath.Join(config.DataDir, fileName)
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {
			log.Error("Failed to close file", "err", err)
		}
	}(file)

	_, err = file.WriteString(keyEnc)
	if err != nil {
		return err
	}

	return nil
}

func readPrivateKey(config *Config, fileName string) (*ecdsa.PrivateKey, error) {
	fullPath := filepath.Join(config.DataDir, fileName)

	keyBytes, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	keyEnc := string(keyBytes)
	key, err := crypto.HexToECDSA(keyEnc)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// setPortalBootstrapNodes creates a list of bootstrap nodes from the command line
// flags, reverting to pre-configured ones if none have been specified.
func setPortalBootstrapNodes(ctx *cli.Context, config *Config) {
	urls := portalwire.PortalBootnodes
	if ctx.IsSet(utils.PortalBootNodesFlag.Name) {
		flag := ctx.String(utils.PortalBootNodesFlag.Name)
		if flag == "none" {
			return
		}
		urls = utils.SplitAndTrim(flag)
	}

	for _, url := range urls {
		if url != "" {
			node, err := enode.Parse(enode.ValidSchemes, url)
			if err != nil {
				log.Error("Bootstrap URL invalid", "enode", url, "err", err)
				continue
			}
			config.Protocol.BootstrapNodes = append(config.Protocol.BootstrapNodes, node)
		}
	}
}

func applyMetricConfig(ctx *cli.Context, cfg *Config) {
	if ctx.IsSet(utils.MetricsEnabledFlag.Name) {
		cfg.Metrics.Enabled = ctx.Bool(utils.MetricsEnabledFlag.Name)
	}
	if ctx.IsSet(utils.MetricsHTTPFlag.Name) {
		cfg.Metrics.HTTP = ctx.String(utils.MetricsHTTPFlag.Name)
	}
	if ctx.IsSet(utils.MetricsPortFlag.Name) {
		cfg.Metrics.Port = ctx.Int(utils.MetricsPortFlag.Name)
	}
	if ctx.IsSet(utils.MetricsEnableInfluxDBFlag.Name) {
		cfg.Metrics.EnableInfluxDB = ctx.Bool(utils.MetricsEnableInfluxDBFlag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBEndpointFlag.Name) {
		cfg.Metrics.InfluxDBEndpoint = ctx.String(utils.MetricsInfluxDBEndpointFlag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBDatabaseFlag.Name) {
		cfg.Metrics.InfluxDBDatabase = ctx.String(utils.MetricsInfluxDBDatabaseFlag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBUsernameFlag.Name) {
		cfg.Metrics.InfluxDBUsername = ctx.String(utils.MetricsInfluxDBUsernameFlag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBPasswordFlag.Name) {
		cfg.Metrics.InfluxDBPassword = ctx.String(utils.MetricsInfluxDBPasswordFlag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBTagsFlag.Name) {
		cfg.Metrics.InfluxDBTags = ctx.String(utils.MetricsInfluxDBTagsFlag.Name)
	}
	if ctx.IsSet(utils.MetricsEnableInfluxDBV2Flag.Name) {
		cfg.Metrics.EnableInfluxDBV2 = ctx.Bool(utils.MetricsEnableInfluxDBV2Flag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBTokenFlag.Name) {
		cfg.Metrics.InfluxDBToken = ctx.String(utils.MetricsInfluxDBTokenFlag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBBucketFlag.Name) {
		cfg.Metrics.InfluxDBBucket = ctx.String(utils.MetricsInfluxDBBucketFlag.Name)
	}
	if ctx.IsSet(utils.MetricsInfluxDBOrganizationFlag.Name) {
		cfg.Metrics.InfluxDBOrganization = ctx.String(utils.MetricsInfluxDBOrganizationFlag.Name)
	}
	// Sanity-check the commandline flags. It is fine if some unused fields is part
	// of the toml-config, but we expect the commandline to only contain relevant
	// arguments, otherwise it indicates an error.
	var (
		enableExport   = ctx.Bool(utils.MetricsEnableInfluxDBFlag.Name)
		enableExportV2 = ctx.Bool(utils.MetricsEnableInfluxDBV2Flag.Name)
	)
	if enableExport || enableExportV2 {
		v1FlagIsSet := ctx.IsSet(utils.MetricsInfluxDBUsernameFlag.Name) ||
			ctx.IsSet(utils.MetricsInfluxDBPasswordFlag.Name)

		v2FlagIsSet := ctx.IsSet(utils.MetricsInfluxDBTokenFlag.Name) ||
			ctx.IsSet(utils.MetricsInfluxDBOrganizationFlag.Name) ||
			ctx.IsSet(utils.MetricsInfluxDBBucketFlag.Name)

		if enableExport && v2FlagIsSet {
			utils.Fatalf("Flags --influxdb.metrics.organization, --influxdb.metrics.token, --influxdb.metrics.bucket are only available for influxdb-v2")
		} else if enableExportV2 && v1FlagIsSet {
			utils.Fatalf("Flags --influxdb.metrics.username, --influxdb.metrics.password are only available for influxdb-v1")
		}
	}
}
