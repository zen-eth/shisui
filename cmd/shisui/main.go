package main

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"os"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/mattn/go-isatty"
	_ "github.com/mattn/go-sqlite3"
	"github.com/optimism-java/shisui2/beacon"
	"github.com/optimism-java/shisui2/ethapi"
	"github.com/optimism-java/shisui2/history"
	"github.com/optimism-java/shisui2/internal/debug"
	"github.com/optimism-java/shisui2/internal/flags"
	"github.com/optimism-java/shisui2/portalwire"
	"github.com/optimism-java/shisui2/state"
	"github.com/optimism-java/shisui2/storage"
	"github.com/optimism-java/shisui2/storage/sqlite"
	"github.com/optimism-java/shisui2/web3"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/urfave/cli/v2"
)

var (
	storageCapacity metrics.Gauge
)

const (
	privateKeyFileName = "clientKey"
)

type Config struct {
	Protocol     *portalwire.PortalProtocolConfig
	PrivateKey   *ecdsa.PrivateKey
	RpcAddr      string
	DataDir      string
	DataCapacity uint64
	LogLevel     int
	Networks     []string
}

type Client struct {
	DiscV5API      *portalwire.DiscV5API
	HistoryNetwork *history.Network
	BeaconNetwork  *beacon.Network
	StateNetwork   *state.Network
	Server         *http.Server
}

var app = flags.NewApp("the go-portal-network command line interface")

var (
	portalProtocolFlags = []cli.Flag{
		utils.PortalNATFlag,
		utils.PortalUDPPortFlag,
		utils.PortalBootNodesFlag,
		utils.PortalPrivateKeyFlag,
		utils.PortalNetworksFlag,
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

	// Start metrics export if enabled
	utils.SetupMetrics(ctx)

	// Start system runtime metrics collection
	go metrics.CollectProcessMetrics(3 * time.Second)
	go portalwire.CollectPortalMetrics(5*time.Second, ctx.StringSlice(utils.PortalNetworksFlag.Name), ctx.String(utils.PortalDataDirFlag.Name))

	if metrics.Enabled {
		storageCapacity = metrics.NewRegisteredGauge("portal/storage_capacity", nil)
		storageCapacity.Update(ctx.Int64(utils.PortalDataCapacityFlag.Name))
	}

	config, err := getPortalConfig(ctx)
	if err != nil {
		return nil
	}

	clientChan := make(chan *Client, 1)
	go handlerInterrupt(clientChan)

	addr, err := net.ResolveUDPAddr("udp", config.Protocol.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	return startPortalRpcServer(*config, conn, config.RpcAddr, clientChan)
}

func setDefaultLogger(logLevel int, logFormat string) error {
	var glogger *log.GlogHandler
	switch {
	case logFormat == "json":
		glogger = log.NewGlogHandler(log.JSONHandler(os.Stderr))
	case logFormat == "logfmt":
		glogger = log.NewGlogHandler(log.LogfmtHandler(os.Stderr))
	case logFormat == "", logFormat == "terminal":
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

func handlerInterrupt(clientChan <-chan *Client) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)

	<-interrupt
	log.Warn("Closing Shisui gracefully (type CTRL-C again to force quit)")

	go func() {
		if len(clientChan) == 0 {
			log.Warn("Waiting for the client to start...")
		}
		c := <-clientChan
		c.closePortalRpcServer()
	}()

	<-interrupt
	os.Exit(1)
}

func (cli *Client) closePortalRpcServer() {
	if cli.HistoryNetwork != nil {
		log.Info("Closing history network...")
		cli.HistoryNetwork.Stop()
	}
	if cli.BeaconNetwork != nil {
		log.Info("Closing beacon network...")
		cli.BeaconNetwork.Stop()
	}
	if cli.StateNetwork != nil {
		log.Info("Closing state network...")
		cli.StateNetwork.Stop()
	}
	log.Info("Closing Database...")
	cli.DiscV5API.DiscV5.LocalNode().Database().Close()
	log.Info("Closing UDPv5 protocol...")
	cli.DiscV5API.DiscV5.Close()
	log.Info("Closing servers...")
	err := cli.Server.Close()
	if err != nil {
		log.Error("Failed to close server", "err", err)
	}
	os.Exit(1)
}

func startPortalRpcServer(config Config, conn discover.UDPConn, addr string, clientChan chan<- *Client) error {
	client := &Client{}

	discV5, localNode, err := initDiscV5(config, conn)
	if err != nil {
		return err
	}

	server := rpc.NewServer()
	discV5API := portalwire.NewDiscV5API(discV5)
	err = server.RegisterName("discv5", discV5API)
	if err != nil {
		return err
	}
	client.DiscV5API = discV5API

	api := &web3.API{}
	err = server.RegisterName("web3", api)
	if err != nil {
		return err
	}
	utp := portalwire.NewPortalUtp(context.Background(), config.Protocol, discV5, conn)

	var historyNetwork *history.Network
	if slices.Contains(config.Networks, portalwire.History.Name()) {
		historyNetwork, err = initHistory(config, server, conn, localNode, discV5, utp)
		if err != nil {
			return err
		}
		client.HistoryNetwork = historyNetwork
	}

	var beaconNetwork *beacon.Network
	if slices.Contains(config.Networks, portalwire.Beacon.Name()) {
		beaconNetwork, err = initBeacon(config, server, conn, localNode, discV5, utp)
		if err != nil {
			return err
		}
		client.BeaconNetwork = beaconNetwork
	}

	var stateNetwork *state.Network
	if slices.Contains(config.Networks, portalwire.State.Name()) {
		stateNetwork, err = initState(config, server, conn, localNode, discV5, utp)
		if err != nil {
			return err
		}
		client.StateNetwork = stateNetwork
	}

	ethApi := &ethapi.API{
		History: historyNetwork,
		// static configuration of ChainId, currently only mainnet implemented
		ChainID: core.DefaultGenesisBlock().Config.ChainID,
	}
	err = server.RegisterName("eth", ethApi)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:    addr,
		Handler: server,
	}
	client.Server = httpServer

	clientChan <- client
	return httpServer.ListenAndServe()
}

func initDiscV5(config Config, conn discover.UDPConn) (*discover.UDPv5, *enode.LocalNode, error) {
	discCfg := discover.Config{
		PrivateKey:  config.PrivateKey,
		NetRestrict: config.Protocol.NetRestrict,
		Bootnodes:   config.Protocol.BootstrapNodes,
		Log:         log.New("protocol", "discV5"),
	}

	nodeDB, err := enode.OpenDB(config.Protocol.NodeDBPath)
	if err != nil {
		return nil, nil, err
	}

	localNode := enode.NewLocalNode(nodeDB, config.PrivateKey)

	localNode.Set(portalwire.Tag)
	listenerAddr := conn.LocalAddr().(*net.UDPAddr)
	natConf := config.Protocol.NAT
	if natConf != nil && !listenerAddr.IP.IsLoopback() {
		doPortMapping(natConf, localNode, listenerAddr)
	}

	discV5, err := discover.ListenV5(conn, localNode, discCfg)
	if err != nil {
		return nil, nil, err
	}
	return discV5, localNode, nil
}

func doPortMapping(natm nat.Interface, ln *enode.LocalNode, addr *net.UDPAddr) {
	const (
		protocol = "udp"
		name     = "ethereum discovery"
	)

	var (
		intport    = addr.Port
		extaddr    = &net.UDPAddr{IP: addr.IP, Port: addr.Port}
		mapTimeout = nat.DefaultMapTimeout
	)
	addMapping := func() {
		// Get the external address.
		var err error
		extaddr.IP, err = natm.ExternalIP()
		if err != nil {
			log.Debug("Couldn't get external IP", "err", err)
			return
		}
		// Create the mapping.
		p, err := natm.AddMapping(protocol, extaddr.Port, intport, name, mapTimeout)
		if err != nil {
			log.Debug("Couldn't add port mapping", "err", err)
			return
		}
		if p != uint16(extaddr.Port) {
			extaddr.Port = int(p)
			log.Info("NAT mapped alternative port")
		} else {
			log.Info("NAT mapped port")
		}
		// Update IP/port information of the local node.
		ln.SetStaticIP(extaddr.IP)
		ln.SetFallbackUDP(extaddr.Port)
	}

	// Perform mapping once, synchronously.
	log.Info("Attempting port mapping")
	addMapping()

	// Refresh the mapping periodically.
	go func() {
		refresh := time.NewTimer(mapTimeout)
		defer refresh.Stop()
		for range refresh.C {
			addMapping()
			refresh.Reset(mapTimeout)
		}
	}()
}

func initHistory(config Config, server *rpc.Server, conn discover.UDPConn, localNode *enode.LocalNode, discV5 *discover.UDPv5, utp *portalwire.PortalUtp) (*history.Network, error) {
	networkName := portalwire.History.Name()
	db, err := sqlite.NewDB(config.DataDir, networkName)
	if err != nil {
		return nil, err
	}
	contentStorage, err := sqlite.NewHistoryStorage(storage.PortalStorageConfig{
		StorageCapacityMB: config.DataCapacity,
		DB:                db,
		NodeId:            localNode.ID(),
		NetworkName:       networkName,
	})
	if err != nil {
		return nil, err
	}
	contentQueue := make(chan *portalwire.ContentElement, 50)

	protocol, err := portalwire.NewPortalProtocol(
		config.Protocol,
		portalwire.History,
		config.PrivateKey,
		conn,
		localNode,
		discV5,
		utp,
		contentStorage,
		contentQueue)

	if err != nil {
		return nil, err
	}
	historyAPI := portalwire.NewPortalAPI(protocol)
	historyNetworkAPI := history.NewHistoryNetworkAPI(historyAPI)
	err = server.RegisterName("portal", historyNetworkAPI)
	if err != nil {
		return nil, err
	}
	accumulator, err := history.NewMasterAccumulator()
	if err != nil {
		return nil, err
	}
	historyNetwork := history.NewHistoryNetwork(protocol, &accumulator)
	return historyNetwork, historyNetwork.Start()
}

func initBeacon(config Config, server *rpc.Server, conn discover.UDPConn, localNode *enode.LocalNode, discV5 *discover.UDPv5, utp *portalwire.PortalUtp) (*beacon.Network, error) {
	dbPath := path.Join(config.DataDir, "beacon")
	err := os.MkdirAll(dbPath, 0755)
	if err != nil {
		return nil, err
	}
	sqlDb, err := sql.Open("sqlite3", path.Join(dbPath, "beacon.sqlite"))
	if err != nil {
		return nil, err
	}

	contentStorage, err := beacon.NewBeaconStorage(storage.PortalStorageConfig{
		StorageCapacityMB: config.DataCapacity,
		DB:                sqlDb,
		NodeId:            localNode.ID(),
		Spec:              configs.Mainnet,
		NetworkName:       portalwire.Beacon.Name(),
	})
	if err != nil {
		return nil, err
	}
	contentQueue := make(chan *portalwire.ContentElement, 50)

	protocol, err := portalwire.NewPortalProtocol(
		config.Protocol,
		portalwire.Beacon,
		config.PrivateKey,
		conn,
		localNode,
		discV5,
		utp,
		contentStorage,
		contentQueue)

	if err != nil {
		return nil, err
	}
	portalApi := portalwire.NewPortalAPI(protocol)

	beaconAPI := beacon.NewBeaconNetworkAPI(portalApi)
	err = server.RegisterName("portal", beaconAPI)
	if err != nil {
		return nil, err
	}

	beaconNetwork := beacon.NewBeaconNetwork(protocol)
	return beaconNetwork, beaconNetwork.Start()
}

func initState(config Config, server *rpc.Server, conn discover.UDPConn, localNode *enode.LocalNode, discV5 *discover.UDPv5, utp *portalwire.PortalUtp) (*state.Network, error) {
	networkName := portalwire.State.Name()
	db, err := sqlite.NewDB(config.DataDir, networkName)
	if err != nil {
		return nil, err
	}
	contentStorage, err := sqlite.NewHistoryStorage(storage.PortalStorageConfig{
		StorageCapacityMB: config.DataCapacity,
		DB:                db,
		NodeId:            localNode.ID(),
		NetworkName:       networkName,
	})
	if err != nil {
		return nil, err
	}
	stateStore := state.NewStateStorage(contentStorage, db)
	contentQueue := make(chan *portalwire.ContentElement, 50)

	protocol, err := portalwire.NewPortalProtocol(
		config.Protocol,
		portalwire.State,
		config.PrivateKey,
		conn,
		localNode,
		discV5,
		utp,
		stateStore,
		contentQueue)

	if err != nil {
		return nil, err
	}
	api := portalwire.NewPortalAPI(protocol)
	stateNetworkAPI := state.NewStateNetworkAPI(api)
	err = server.RegisterName("portal", stateNetworkAPI)
	if err != nil {
		return nil, err
	}
	client := rpc.DialInProc(server)
	historyNetwork := state.NewStateNetwork(protocol, client)
	return historyNetwork, historyNetwork.Start()
}

func getPortalConfig(ctx *cli.Context) (*Config, error) {
	config := &Config{
		Protocol: portalwire.DefaultPortalProtocolConfig(),
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
	urls := params.PortalBootnodes
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
