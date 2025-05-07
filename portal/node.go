package portal

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/zen-eth/shisui/beacon"
	"github.com/zen-eth/shisui/ethapi"
	"github.com/zen-eth/shisui/history"
	"github.com/zen-eth/shisui/portalwire"
	"github.com/zen-eth/shisui/state"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/storage/pebble"
	"github.com/zen-eth/shisui/web3"
)

// Config holds configuration for the Shisui client
type Config struct {
	PortalProtocolConfig  *portalwire.PortalProtocolConfig
	PrivateKey            *ecdsa.PrivateKey
	IsGnetEnabled         bool
	RpcAddr               string
	DataDir               string
	DataCapacity          uint64
	LogLevel              int
	Networks              []string
	Metrics               *metrics.Config
	DisableTableInitCheck bool
	ExternalOracle        string
}

func DefaultConfig() *Config {
	return &Config{
		PortalProtocolConfig: portalwire.DefaultPortalProtocolConfig(),
		Metrics:              &metrics.DefaultConfig,
		IsGnetEnabled:        false,
		RpcAddr:              "localhost:8545",
		DataDir:              "./",
		DataCapacity:         1000 * 10,
		LogLevel:             3,
		Networks:             []string{"history"},
	}
}

// Node represents a Shisui node with all its services
type Node struct {
	config         *Config
	discV5         *discover.UDPv5
	localNode      *enode.LocalNode
	conn           discover.UDPConn
	utp            *portalwire.UtpTransportService
	discV5API      *portalwire.DiscV5API
	rpcServer      *rpc.Server
	httpServer     *http.Server
	historyNetwork *history.Network
	beaconNetwork  *beacon.Network
	stateNetwork   *state.Network
	stop           chan struct{} // Channel to wait for termination notifications
}

// NewNode creates a new Node with the given config
func NewNode(config *Config) (*Node, error) {
	node := &Node{
		config: config,
		stop:   make(chan struct{}),
	}

	// Initialize UDP connection
	err := node.initUDP()
	if err != nil {
		return nil, err
	}

	// Initialize base components
	err = node.initDiscV5()
	if err != nil {
		return nil, err
	}

	node.utp = portalwire.NewZenEthUtp(context.Background(), config.PortalProtocolConfig, node.discV5, node.conn)

	// Initialize RPC server
	node.rpcServer = rpc.NewServer()
	node.discV5API = portalwire.NewDiscV5API(node.discV5)
	err = node.rpcServer.RegisterName("discv5", node.discV5API)
	if err != nil {
		return nil, err
	}

	// Register Web3 API
	api := &web3.API{}
	err = node.rpcServer.RegisterName("web3", api)
	if err != nil {
		return nil, err
	}

	// Initialize services based on config
	if slices.Contains(config.Networks, portalwire.Beacon.Name()) {
		err = node.initBeaconNetwork()
		if err != nil {
			return nil, err
		}
	}

	if slices.Contains(config.Networks, portalwire.History.Name()) {
		err = node.initHistoryNetwork()
		if err != nil {
			return nil, err
		}
	}

	if slices.Contains(config.Networks, portalwire.State.Name()) {
		err = node.initStateNetwork()
		if err != nil {
			return nil, err
		}
	}

	// Register Ethereum API
	ethApi := &ethapi.API{
		History: node.historyNetwork,
		ChainID: core.DefaultGenesisBlock().Config.ChainID,
	}
	err = node.rpcServer.RegisterName("eth", ethApi)
	if err != nil {
		return nil, err
	}

	// Prepare HTTP server
	node.httpServer = &http.Server{
		Addr:    config.RpcAddr,
		Handler: node.rpcServer,
	}

	return node, nil
}

// Start starts all node services
func (n *Node) Start() error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var startErr error

	startNetwork := func(start func() error, name string) {
		defer wg.Done()
		if err := start(); err != nil {
			mu.Lock()
			startErr = fmt.Errorf("failed to start %s network: %w", name, err)
			mu.Unlock()
		}
	}

	if n.historyNetwork != nil {
		wg.Add(1)
		go startNetwork(n.historyNetwork.Start, "history")
	}

	if n.beaconNetwork != nil {
		wg.Add(1)
		go startNetwork(n.beaconNetwork.Start, "beacon")
	}

	if n.stateNetwork != nil {
		wg.Add(1)
		go startNetwork(n.stateNetwork.Start, "state")
	}

	wg.Wait()

	if startErr != nil {
		return startErr
	}

	go func() {
		if err := n.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server error", "err", err)
		}
	}()

	return nil
}

// Stop gracefully stops all node services
func (n *Node) Stop() {
	var wg sync.WaitGroup

	if n.historyNetwork != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("Closing history network...")
			n.historyNetwork.Stop()
		}()
	}

	if n.beaconNetwork != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("Closing beacon network...")
			n.beaconNetwork.Stop()
		}()
	}

	if n.stateNetwork != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("Closing state network...")
			n.stateNetwork.Stop()
		}()
	}

	wg.Wait()

	if n.localNode != nil && n.localNode.Database() != nil {
		log.Info("Closing Database...")
		n.localNode.Database().Close()
	}

	if n.utp != nil {
		log.Info("Closing UTP protocol...")
		n.utp.Stop()
	}

	if n.discV5 != nil {
		log.Info("Closing UDPv5 protocol...")
		n.discV5.Close()
	}

	if n.httpServer != nil {
		log.Info("Closing HTTP server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := n.httpServer.Shutdown(ctx); err != nil {
			log.Error("Failed to gracefully shut down server", "err", err)
		}
	}

	log.Info("Services stopped")
	close(n.stop)
}

// Wait waits for the node to stop
func (n *Node) Wait() {
	<-n.stop
}

func (n *Node) initUDP() error {
	var err error
	if n.config.IsGnetEnabled {
		conn := portalwire.NewGnetConn(log.New("discv5", "gnet"))
		err = conn.ListenUDP(context.Background(), n.config.PortalProtocolConfig.ListenAddr)
		if err != nil {
			return err
		}
		n.conn = conn
		return nil
	} else {
		var addr *net.UDPAddr
		addr, err = net.ResolveUDPAddr("udp", n.config.PortalProtocolConfig.ListenAddr)
		if err != nil {
			return err
		}
		n.conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		return nil
	}
}

// initDiscV5 initializes the discV5 protocol and local node
func (n *Node) initDiscV5() error {
	discCfg := discover.Config{
		PrivateKey:  n.config.PrivateKey,
		NetRestrict: n.config.PortalProtocolConfig.NetRestrict,
		Bootnodes:   n.config.PortalProtocolConfig.BootstrapNodes,
		Log:         log.New("protocol", "discV5"),
	}

	nodeDB, err := enode.OpenDB(n.config.PortalProtocolConfig.NodeDBPath)
	if err != nil {
		return err
	}

	n.localNode = enode.NewLocalNode(nodeDB, n.config.PrivateKey)

	// initialize portal versions on enode enr
	n.localNode.Set(portalwire.Versions)

	n.localNode.Set(portalwire.Tag)
	listenerAddr := n.conn.LocalAddr().(*net.UDPAddr)
	natConf := n.config.PortalProtocolConfig.NAT
	if natConf != nil && !listenerAddr.IP.IsLoopback() {
		doPortMapping(natConf, n.localNode, listenerAddr)
	}

	n.discV5, err = discover.ListenV5(n.conn, n.localNode, discCfg)
	return err
}

// initHistoryNetwork initializes the history network
func (n *Node) initHistoryNetwork() error {
	networkName := portalwire.History.Name()
	db, err := pebble.NewDB(n.config.DataDir, 16, 400, networkName)
	if err != nil {
		return err
	}

	contentStorage, err := pebble.NewStorage(storage.PortalStorageConfig{
		StorageCapacityMB: n.config.DataCapacity,
		NodeId:            n.localNode.ID(),
		NetworkName:       networkName,
	}, db)
	if err != nil {
		return err
	}

	contentQueue := make(chan *portalwire.ContentElement, 50)

	protocol, err := portalwire.NewPortalProtocol(
		n.config.PortalProtocolConfig,
		portalwire.History,
		n.config.PrivateKey,
		n.conn,
		n.localNode,
		n.discV5,
		n.utp,
		contentStorage,
		contentQueue, portalwire.WithDisableTableInitCheckOption(n.config.DisableTableInitCheck))

	if err != nil {
		return err
	}

	historyAPI := portalwire.NewPortalAPI(protocol)
	historyNetworkAPI := history.NewHistoryNetworkAPI(historyAPI)
	err = n.rpcServer.RegisterName("portal", historyNetworkAPI)
	if err != nil {
		return err
	}

	accumulator, err := history.NewMasterAccumulator()
	if err != nil {
		return err
	}

	externalOracle := history.NewExternalOracle(n.config.ExternalOracle, n.beaconNetwork)

	client := rpc.DialInProc(n.rpcServer)
	n.historyNetwork = history.NewHistoryNetwork(protocol, &accumulator, client, externalOracle)
	return nil
}

// initBeaconNetwork initializes the beacon network
func (n *Node) initBeaconNetwork() error {
	networkName := portalwire.Beacon.Name()
	db, err := pebble.NewDB(n.config.DataDir, 16, 400, networkName)
	if err != nil {
		return err
	}

	contentStorage, err := beacon.NewBeaconStorage(storage.PortalStorageConfig{
		StorageCapacityMB: n.config.DataCapacity,
		NodeId:            n.localNode.ID(),
		Spec:              configs.Mainnet,
		NetworkName:       portalwire.Beacon.Name(),
	}, db)
	if err != nil {
		return err
	}

	contentQueue := make(chan *portalwire.ContentElement, 50)

	protocol, err := portalwire.NewPortalProtocol(
		n.config.PortalProtocolConfig,
		portalwire.Beacon,
		n.config.PrivateKey,
		n.conn,
		n.localNode,
		n.discV5,
		n.utp,
		contentStorage,
		contentQueue, portalwire.WithDisableTableInitCheckOption(n.config.DisableTableInitCheck))

	if err != nil {
		return err
	}

	portalApi := portalwire.NewPortalAPI(protocol)

	beaconConfig := beacon.DefaultConfig()
	if len(n.config.PortalProtocolConfig.TrustedBlockRoot) > 0 {
		beaconConfig.DefaultCheckpoint = common.Root(n.config.PortalProtocolConfig.TrustedBlockRoot)
	}

	portalRpc := beacon.NewPortalLightApi(protocol, beaconConfig.Spec)
	beaconClient, err := beacon.NewConsensusLightClient(portalRpc, &beaconConfig, beaconConfig.DefaultCheckpoint, log.New("beacon", "light-client"))
	if err != nil {
		return err
	}

	beaconAPI := beacon.NewBeaconNetworkAPI(portalApi, beaconClient)
	err = n.rpcServer.RegisterName("portal", beaconAPI)
	if err != nil {
		return err
	}

	n.beaconNetwork = beacon.NewBeaconNetwork(protocol, beaconClient)
	return nil
}

// initStateNetwork initializes the state network
func (n *Node) initStateNetwork() error {
	networkName := portalwire.State.Name()
	db, err := pebble.NewDB(n.config.DataDir, 16, 400, networkName)
	if err != nil {
		return err
	}

	contentStorage, err := pebble.NewStorage(storage.PortalStorageConfig{
		StorageCapacityMB: n.config.DataCapacity,
		NodeId:            n.localNode.ID(),
		NetworkName:       networkName,
	}, db)
	if err != nil {
		return err
	}

	stateStore := state.NewStateStorage(contentStorage, db)
	contentQueue := make(chan *portalwire.ContentElement, n.config.PortalProtocolConfig.MaxUtpConnSize)

	protocol, err := portalwire.NewPortalProtocol(
		n.config.PortalProtocolConfig,
		portalwire.State,
		n.config.PrivateKey,
		n.conn,
		n.localNode,
		n.discV5,
		n.utp,
		stateStore,
		contentQueue, portalwire.WithDisableTableInitCheckOption(n.config.DisableTableInitCheck))

	if err != nil {
		return err
	}

	api := portalwire.NewPortalAPI(protocol)
	stateNetworkAPI := state.NewStateNetworkAPI(api)
	err = n.rpcServer.RegisterName("portal", stateNetworkAPI)
	if err != nil {
		return err
	}

	client := rpc.DialInProc(n.rpcServer)
	n.stateNetwork = state.NewStateNetwork(protocol, client)
	return nil
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
