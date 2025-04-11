package portalwire

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sync/semaphore"
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
	startOnce     sync.Once
	ctx           context.Context
	log           log.Logger
	discV5        *discover.UDPv5
	socket        *zenutp.UtpSocket
	socketConfig  *zenutp.ConnectionConfig
	ListenAddr    string
	utpController *UtpController
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
		hash: dst.ID().String(),
	}
}

func newUtpPeerWithNodeNAddr(dst *enode.Node, addr *netip.AddrPort) *UtpPeer {
	return &UtpPeer{
		id:   dst.ID(),
		node: dst,
		addr: addr,
		hash: dst.ID().String(),
	}
}

func (p *UtpPeer) Hash() string {
	return p.hash
}

func (p *UtpPeer) String() string {
	return fmt.Sprintf("{id: %s, addr: %s, }", p.id.String(), p.addr.String())
}

type packetItem struct {
	peer *UtpPeer
	data []byte
}

// ReleasePermit permit of Utp conn, if apply for permit success, will return a permit function.
// And must uses it to release permit.
type ReleasePermit func()

var NoPermit ReleasePermit = func() {}

type UtpController struct {
	inboundLimit  *semaphore.Weighted
	outboundLimit *semaphore.Weighted
}

func NewUtpController(maxLimit int) *UtpController {
	return &UtpController{
		inboundLimit:  semaphore.NewWeighted(int64(maxLimit)),
		outboundLimit: semaphore.NewWeighted(int64(maxLimit)),
	}
}

func (u *UtpController) GetInboundPermit() (ReleasePermit, bool) {
	if ok := u.inboundLimit.TryAcquire(1); !ok {
		return NoPermit, false
	}
	return func() {
		u.inboundLimit.Release(1)
	}, true
}

func (u *UtpController) GetOutboundPermit() (ReleasePermit, bool) {
	if ok := u.outboundLimit.TryAcquire(1); !ok {
		return NoPermit, false
	}
	return func() {
		u.outboundLimit.Release(1)
	}, true
}

type discv5Conn struct {
	logger        log.Logger
	receive       chan *packetItem
	conn          *discover.UDPv5
	closed        *atomic.Bool
	UtpController *UtpController
}

func newDiscv5Conn(conn *discover.UDPv5, logger log.Logger) *discv5Conn {
	return &discv5Conn{
		conn:    conn,
		logger:  logger,
		receive: make(chan *packetItem, 1024),
		closed:  &atomic.Bool{},
	}
}

func (c *discv5Conn) handleUtpTalkRequest(node *enode.Node, addr *net.UDPAddr, data []byte) []byte {
	addrPort := netip.AddrPortFrom(netutil.IPToAddr(addr.IP), uint16(addr.Port))
	peer := newUtpPeerWithNodeNAddr(node, &addrPort)
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
		return 0, errors.New("discv5 conn has closed")
	}
	peer, ok := dst.(*UtpPeer)
	if !ok {
		return 0, errors.New("dest peer is not a utp peer")
	}
	req := &v5wire.TalkRequest{Protocol: UTP_STRING, Message: b}
	c.conn.SendNoResp(peer.node, *peer.addr, req)
	return len(b), nil
}

func (c *discv5Conn) Close() error {
	c.closed.Store(true)
	close(c.receive)
	return nil
}

func NewZenEthUtp(ctx context.Context, config *PortalProtocolConfig, discV5 *discover.UDPv5, conn discover.UDPConn) *ZenEthUtp {
	return &ZenEthUtp{
		ctx:           ctx,
		log:           log.New("protocol", "utp", "local", conn.LocalAddr().String()),
		discV5:        discV5,
		socketConfig:  zenutp.NewConnectionConfig(),
		ListenAddr:    config.ListenAddr,
		utpController: NewUtpController(config.MaxUtpConnSize),
	}
}

func (z *ZenEthUtp) Start() error {
	z.startOnce.Do(func() {
		conn := newDiscv5Conn(z.discV5, z.log)
		z.socket = zenutp.WithSocket(z.ctx, conn, z.log)
		z.discV5.RegisterTalkHandler(UTP_STRING, conn.handleUtpTalkRequest)
	})
	return nil
}

func (z *ZenEthUtp) GetOutboundPermit() (ReleasePermit, bool) {
	return z.utpController.GetOutboundPermit()
}

func (z *ZenEthUtp) GetInboundPermit() (ReleasePermit, bool) {
	return z.utpController.GetInboundPermit()
}

func (z *ZenEthUtp) DialWithCid(ctx context.Context, dest *enode.Node, connId uint16) (*zenutp.UtpStream, error) {
	cid := z.SendId(dest, connId)
	stream, err := z.socket.ConnectWithCid(ctx, cid, z.socketConfig)
	return stream, err
}

func (z *ZenEthUtp) Dial(ctx context.Context, dest *enode.Node) (*zenutp.UtpStream, error) {
	addrPort := netip.AddrPortFrom(dest.IPAddr(), uint16(dest.UDP()))
	peer := &UtpPeer{id: dest.ID(), addr: &addrPort}
	z.log.Info("will connect to: ", "addr", addrPort.String())

	stream, err := z.socket.Connect(ctx, peer, z.socketConfig)
	return stream, err
}

func (z *ZenEthUtp) AcceptWithCid(ctx context.Context, cid *zenutp.ConnectionId) (*zenutp.UtpStream, error) {
	z.log.Debug("will accept from: ", "nodeId", cid.Peer.Hash(), "sendId", cid.Send, "recvId", cid.Recv)
	stream, err := z.socket.AcceptWithCid(ctx, cid, z.socketConfig)
	return stream, err
}

func (z *ZenEthUtp) Accept(ctx context.Context) (*zenutp.UtpStream, error) {
	stream, err := z.socket.Accept(ctx, z.socketConfig)
	return stream, err
}

func (z *ZenEthUtp) Stop() {
	z.socket.Close()
}

func (z *ZenEthUtp) Cid(dst *enode.Node, isInitiator bool) *zenutp.ConnectionId {
	peer := newUtpPeer(dst)
	return z.socket.Cid(peer, isInitiator)
}

func (z *ZenEthUtp) CidWithAddr(dst *enode.Node, addr *net.UDPAddr, isInitiator bool) *zenutp.ConnectionId {
	addrPort := netip.AddrPortFrom(netutil.IPToAddr(addr.IP), uint16(addr.Port))
	peer := newUtpPeerWithNodeNAddr(dst, &addrPort)
	return z.socket.Cid(peer, isInitiator)
}

func (z *ZenEthUtp) RecvId(dst *enode.Node, connId uint16) *zenutp.ConnectionId {
	peer := newUtpPeer(dst)
	return zenutp.NewConnectionId(peer, connId+1, connId)
}

func (z *ZenEthUtp) SendId(dst *enode.Node, connId uint16) *zenutp.ConnectionId {
	peer := newUtpPeer(dst)
	return zenutp.NewConnectionId(peer, connId, connId+1)
}
