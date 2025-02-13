package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"os"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/mattn/go-isatty"
	_ "github.com/mattn/go-sqlite3"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/urfave/cli/v2"
	"github.com/zen-eth/shisui/beacon"
	"github.com/zen-eth/shisui/cmd/shisui/utils"
	"github.com/zen-eth/shisui/ethapi"
	"github.com/zen-eth/shisui/history"
	"github.com/zen-eth/shisui/internal/debug"
	"github.com/zen-eth/shisui/internal/flags"
	"github.com/zen-eth/shisui/portalwire"
	"github.com/zen-eth/shisui/state"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/storage/pebble"
	"github.com/zen-eth/shisui/web3"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	storageCapacity *metrics.Gauge
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
	Metrics      *metrics.Config
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
		utils.PortalDiscv5GnetFlag,
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
		return nil
	}

	conn, err := newConn(ctx, config.Protocol.ListenAddr)

	if err != nil {
		return err
	}

	// Start metrics export if enabled
	utils.SetupMetrics(config.Metrics)

	go portalwire.CollectPortalMetrics(5*time.Second, ctx.StringSlice(utils.PortalNetworksFlag.Name), ctx.String(utils.PortalDataDirFlag.Name))

	if metrics.Enabled() {
		storageCapacity = metrics.NewRegisteredGauge("portal/storage_capacity", nil)
		storageCapacity.Update(ctx.Int64(utils.PortalDataCapacityFlag.Name))
	}

	clientChan := make(chan *Client, 1)
	go handlerInterrupt(clientChan)
	return startPortalRpcServer(*config, conn, config.RpcAddr, clientChan)
}

func newConn(ctx *cli.Context, addrStr string) (discover.UDPConn, error) {
	if useGnet := ctx.Bool(utils.PortalDiscv5GnetFlag.Name); useGnet {
		conn := portalwire.NewGnetConn(log.New("discv5", "gnet"))
		err := conn.ListenUDP(context.Background(), addrStr)
		return conn, err
	} else {
		addr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", addr)
		return conn, err
	}
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
	utp := portalwire.NewZenEthUtp(context.Background(), config.Protocol, discV5, conn)

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

func initHistory(config Config, server *rpc.Server, conn discover.UDPConn, localNode *enode.LocalNode, discV5 *discover.UDPv5, utp *portalwire.ZenEthUtp) (*history.Network, error) {
	networkName := portalwire.History.Name()
	db, err := pebble.NewDB(config.DataDir, 16, 400, networkName)
	if err != nil {
		return nil, err
	}
	contentStorage, err := pebble.NewStorage(storage.PortalStorageConfig{
		StorageCapacityMB: config.DataCapacity,
		NodeId:            localNode.ID(),
		NetworkName:       networkName,
	}, db)
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

func initBeacon(config Config, server *rpc.Server, conn discover.UDPConn, localNode *enode.LocalNode, discV5 *discover.UDPv5, utp *portalwire.ZenEthUtp) (*beacon.Network, error) {
	networkName := portalwire.Beacon.Name()
	db, err := pebble.NewDB(config.DataDir, 16, 400, networkName)
	if err != nil {
		return nil, err
	}
	contentStorage, err := beacon.NewBeaconStorage(storage.PortalStorageConfig{
		StorageCapacityMB: config.DataCapacity,
		NodeId:            localNode.ID(),
		Spec:              configs.Mainnet,
		NetworkName:       portalwire.Beacon.Name(),
	}, db)
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

	beaconConfig := beacon.DefaultConfig()
	portalRpc := beacon.NewPortalLightApi(protocol, beaconConfig.Spec)
	beaconClient, err := beacon.NewConsensusLightClient(portalRpc, &beaconConfig, beaconConfig.DefaultCheckpoint, log.New("beacon", "light-client"))
	if err != nil {
		return nil, err
	}

	beaconAPI := beacon.NewBeaconNetworkAPI(portalApi, beaconClient)
	err = server.RegisterName("portal", beaconAPI)
	if err != nil {
		return nil, err
	}

	beaconNetwork := beacon.NewBeaconNetwork(protocol, beaconClient)
	return beaconNetwork, beaconNetwork.Start()
}

func initState(config Config, server *rpc.Server, conn discover.UDPConn, localNode *enode.LocalNode, discV5 *discover.UDPv5, utp *portalwire.ZenEthUtp) (*state.Network, error) {
	networkName := portalwire.State.Name()
	db, err := pebble.NewDB(config.DataDir, 16, 400, networkName)
	if err != nil {
		return nil, err
	}
	contentStorage, err := pebble.NewStorage(storage.PortalStorageConfig{
		StorageCapacityMB: config.DataCapacity,
		NodeId:            localNode.ID(),
		NetworkName:       networkName,
	}, db)
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
