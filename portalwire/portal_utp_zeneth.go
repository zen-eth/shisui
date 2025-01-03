package portalwire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	zenutp "github.com/zen-eth/utp-go"
)

var (
	UTP_TALKRESPONSE = []byte{}
	UTP_STRING       = string(Utp)
)

type ZenEthUtp struct {
	startOnce    sync.Once
	ctx          context.Context
	log          log.Logger
	discV5       *discover.UDPv5
	socket       *zenutp.UtpSocket
	socketConfig *zenutp.ConnectionConfig
	ListenAddr   string
}

type UtpPeer struct {
	id   enode.ID
	node *enode.Node
	addr *netip.AddrPort
	hash string
}

func newUtpPeer(dst *enode.Node) *UtpPeer {
	addrPort, ok := dst.UDPEndpoint()
	if !ok {
		return nil
	}
	return &UtpPeer{
		id:   dst.ID(),
		node: dst,
		addr: &addrPort,
	}
}

func newUtpPeerFromId(id enode.ID, addr *netip.AddrPort) *UtpPeer {
	return &UtpPeer{
		id:   id,
		addr: addr,
	}
}

func (p *UtpPeer) Hash() string {
	if p.hash == "" {
		p.hash = p.id.String()
	}
	return p.hash
}

func (p *UtpPeer) String() string {
	return fmt.Sprintf("{id: %s, addr: %s, }", p.id.String(), p.addr.String())
}

type packetItem struct {
	peer *UtpPeer
	data []byte
}

type discv5Conn struct {
	logger  log.Logger
	receive chan *packetItem
	conn    *discover.UDPv5
	closed  *atomic.Bool
}

func newDiscv5Conn(conn *discover.UDPv5, logger log.Logger) *discv5Conn {
	return &discv5Conn{
		conn:    conn,
		logger:  logger,
		receive: make(chan *packetItem, 1024),
		closed:  &atomic.Bool{},
	}
}

func (c *discv5Conn) handleUtpTalkRequest(id enode.ID, addr *net.UDPAddr, data []byte) []byte {
	addrPort := netip.AddrPortFrom(netutil.IPToAddr(addr.IP), uint16(addr.Port))
	peer := &UtpPeer{id: id, addr: &addrPort}
	c.receive <- &packetItem{peer, data}
	return UTP_TALKRESPONSE
}

func (c *discv5Conn) ReadFrom(b []byte) (int, zenutp.ConnectionPeer, error) {
	if c.closed.Load() {
		return 0, nil, io.EOF
	}
	item, ok := <-c.receive
	if ok {
		copy(b, item.data)
		return len(item.data), item.peer, nil
	}
	return 0, nil, errors.New("socket has closed")
}

func (c *discv5Conn) WriteTo(b []byte, dst zenutp.ConnectionPeer) (int, error) {
	if c.closed.Load() {
		return 0, nil
	}
	peer := dst.(*UtpPeer)
	var node *enode.Node
	if peer.node == nil {
		addr := peer.addr.String()
		node, _ = c.conn.GetCachedNode(addr)
		if node == nil {
			c.logger.Warn("not found in cache, will get from discv5 table", "addr", addr)
			node = c.conn.GetNode(peer.id)
		}
		if node == nil {
			c.logger.Warn("not found peer", "id", peer.id.String(), "addr", addr)
			return 0, fmt.Errorf("not found target node id")
		}
	} else {
		node = peer.node
	}
	req := &v5wire.TalkRequest{Protocol: UTP_STRING, Message: b}
	c.conn.SendFromAnotherThreadWithNode(node, *peer.addr, req)
	return len(b), nil
}

func (c *discv5Conn) Close() error {
	c.closed.Store(true)
	close(c.receive)
	return nil
}

func NewZenEthUtp(ctx context.Context, config *PortalProtocolConfig, discV5 *discover.UDPv5, conn discover.UDPConn) *ZenEthUtp {
	return &ZenEthUtp{
		ctx:          ctx,
		log:          log.New("protocol", "utp", "local", conn.LocalAddr().String()),
		discV5:       discV5,
		socketConfig: zenutp.NewConnectionConfig(),
		ListenAddr:   config.ListenAddr,
	}
}

func (p *ZenEthUtp) Start() error {
	p.startOnce.Do(func() {
		conn := newDiscv5Conn(p.discV5, p.log)
		p.socket = zenutp.WithSocket(p.ctx, conn, p.log)
		p.discV5.RegisterTalkHandler(UTP_STRING, conn.handleUtpTalkRequest)
	})
	return nil
}

func (p *ZenEthUtp) DialWithCid(ctx context.Context, dest *enode.Node, connId uint16) (*zenutp.UtpStream, error) {
	cid := p.SendId(dest, connId)
	stream, err := p.socket.ConnectWithCid(ctx, cid, p.socketConfig)
	return stream, err
}

func (p *ZenEthUtp) Dial(ctx context.Context, dest *enode.Node) (*zenutp.UtpStream, error) {
	addrPort := netip.AddrPortFrom(dest.IPAddr(), uint16(dest.UDP()))
	peer := &UtpPeer{id: dest.ID(), addr: &addrPort}
	p.log.Info("will connect to: ", "addr", addrPort.String())

	stream, err := p.socket.Connect(ctx, peer, p.socketConfig)
	return stream, err
}

func (p *ZenEthUtp) AcceptWithCid(ctx context.Context, cid *zenutp.ConnectionId) (*zenutp.UtpStream, error) {
	p.log.Debug("will accept from: ", "nodeId", cid.Peer.Hash(), "sendId", cid.Send, "recvId", cid.Recv)
	stream, err := p.socket.AcceptWithCid(ctx, cid, p.socketConfig)
	return stream, err
}

func (p *ZenEthUtp) Accept(ctx context.Context) (*zenutp.UtpStream, error) {
	stream, err := p.socket.Accept(ctx, p.socketConfig)
	return stream, err
}

func (p *ZenEthUtp) Stop() {
	p.socket.Close()
}

func (p *ZenEthUtp) Cid(dst *enode.Node, isInitiator bool) *zenutp.ConnectionId {
	peer := newUtpPeer(dst)
	return p.socket.Cid(peer, isInitiator)
}

func (p *ZenEthUtp) CidFromId(id enode.ID, addr *net.UDPAddr, isInitiator bool) *zenutp.ConnectionId {
	addrPort := netip.AddrPortFrom(netutil.IPToAddr(addr.IP), uint16(addr.Port))
	peer := newUtpPeerFromId(id, &addrPort)
	return p.socket.Cid(peer, isInitiator)
}

func (p *ZenEthUtp) RecvId(dst *enode.Node, connId uint16) *zenutp.ConnectionId {
	peer := newUtpPeer(dst)
	return &zenutp.ConnectionId{
		Peer: peer,
		Recv: connId + 1,
		Send: connId,
	}
}

func (p *ZenEthUtp) SendId(dst *enode.Node, connId uint16) *zenutp.ConnectionId {
	peer := newUtpPeer(dst)
	return &zenutp.ConnectionId{
		Peer: peer,
		Recv: connId,
		Send: connId + 1,
	}
}
