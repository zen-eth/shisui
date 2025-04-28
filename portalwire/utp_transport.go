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
	utp "github.com/zen-eth/utp-go"
)

var (
	UTP_TALKRESPONSE = []byte{}
	UTP_STRING       = string(Utp)
)

type UtpTransportService struct {
	startOnce     sync.Once
	ctx           context.Context
	log           log.Logger
	discV5        *discover.UDPv5
	socket        *utp.UtpSocket
	socketConfig  *utp.ConnectionConfig
	ListenAddr    string
	utpController *utpController
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

// ReleasePermit is a interface type that releases a UTP connection permit.
type Permit interface {
	Release()
}

type NoPermit struct{}

func (n *NoPermit) Release() {}

// ReleasePermit is a function type that releases a UTP connection permit.
// It is returned when a permit is successfully acquired and must be called to release the permit.
type ReleasePermit struct {
	released atomic.Bool
	action   func()
}

func (p *ReleasePermit) Release() {
	if p.released.CompareAndSwap(false, true) {
		p.action()
	}
}

type utpController struct {
	inboundLimit  *semaphore.Weighted
	outboundLimit *semaphore.Weighted
}

func newUtpController(maxLimit int) *utpController {
	return &utpController{
		inboundLimit:  semaphore.NewWeighted(int64(maxLimit)),
		outboundLimit: semaphore.NewWeighted(int64(maxLimit)),
	}
}

// GetInboundPermit tries to acquire a permit for inbound UTP connections.
// It is returned when a permit is successfully acquired and must be called to release the permit.
func (u *utpController) GetInboundPermit() (Permit, bool) {
	if ok := u.inboundLimit.TryAcquire(1); !ok {
		return &NoPermit{}, false
	}
	return &ReleasePermit{
		action: func() {
			u.inboundLimit.Release(1)
		},
	}, true
}

// GetInboundPermit tries to acquire a permit for outbound UTP connections.
// It is returned when a permit is successfully acquired and must be called to release the permit.
func (u *utpController) GetOutboundPermit() (Permit, bool) {
	if ok := u.outboundLimit.TryAcquire(1); !ok {
		return &NoPermit{}, false
	}
	return &ReleasePermit{
		action: func() {
			u.outboundLimit.Release(1)
		},
	}, true
}

type discv5Conn struct {
	logger        log.Logger
	receive       chan *packetItem
	conn          *discover.UDPv5
	closed        *atomic.Bool
	UtpController *utpController
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

func (c *discv5Conn) ReadFrom(b []byte) (int, utp.ConnectionPeer, error) {
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

func (c *discv5Conn) WriteTo(b []byte, dst utp.ConnectionPeer) (int, error) {
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

func NewZenEthUtp(ctx context.Context, config *PortalProtocolConfig, discV5 *discover.UDPv5, conn discover.UDPConn) *UtpTransportService {
	uts := &UtpTransportService{
		ctx:           ctx,
		log:           log.New("protocol", "utp", "local", conn.LocalAddr().String()),
		discV5:        discV5,
		socketConfig:  utp.NewConnectionConfig(),
		ListenAddr:    config.ListenAddr,
		utpController: newUtpController(config.MaxUtpConnSize),
	}

	uts.log.Warn("utp transport limit size", "size", config.MaxUtpConnSize)

	return uts
}

func (z *UtpTransportService) Start() error {
	z.startOnce.Do(func() {
		conn := newDiscv5Conn(z.discV5, z.log)
		z.socket = utp.WithSocket(z.ctx, conn, z.log)
		z.discV5.RegisterTalkHandler(UTP_STRING, conn.handleUtpTalkRequest)
	})
	return nil
}

func (z *UtpTransportService) GetOutboundPermit() (Permit, bool) {
	return z.utpController.GetOutboundPermit()
}

func (z *UtpTransportService) GetInboundPermit() (Permit, bool) {
	return z.utpController.GetInboundPermit()
}

func (z *UtpTransportService) DialWithCid(ctx context.Context, dest *enode.Node, connId uint16) (*utp.UtpStream, error) {
	cid := z.SendId(dest, connId)
	stream, err := z.socket.ConnectWithCid(ctx, cid, z.socketConfig)
	return stream, err
}

func (z *UtpTransportService) Dial(ctx context.Context, dest *enode.Node) (*utp.UtpStream, error) {
	addrPort := netip.AddrPortFrom(dest.IPAddr(), uint16(dest.UDP()))
	peer := &UtpPeer{id: dest.ID(), addr: &addrPort}
	z.log.Info("will connect to: ", "addr", addrPort.String())

	stream, err := z.socket.Connect(ctx, peer, z.socketConfig)
	return stream, err
}

func (z *UtpTransportService) AcceptWithCid(ctx context.Context, cid *utp.ConnectionId) (*utp.UtpStream, error) {
	z.log.Debug("will accept from: ", "nodeId", cid.Peer.Hash(), "sendId", cid.Send, "recvId", cid.Recv)
	stream, err := z.socket.AcceptWithCid(ctx, cid, z.socketConfig)
	return stream, err
}

func (z *UtpTransportService) Accept(ctx context.Context) (*utp.UtpStream, error) {
	stream, err := z.socket.Accept(ctx, z.socketConfig)
	return stream, err
}

func (z *UtpTransportService) Stop() {
	z.socket.Close()
}

func (z *UtpTransportService) Cid(dst *enode.Node, isInitiator bool) *utp.ConnectionId {
	peer := newUtpPeer(dst)
	return z.socket.Cid(peer, isInitiator)
}

func (z *UtpTransportService) CidWithAddr(dst *enode.Node, addr *net.UDPAddr, isInitiator bool) *utp.ConnectionId {
	addrPort := netip.AddrPortFrom(netutil.IPToAddr(addr.IP), uint16(addr.Port))
	peer := newUtpPeerWithNodeNAddr(dst, &addrPort)
	return z.socket.Cid(peer, isInitiator)
}

func (z *UtpTransportService) RecvId(dst *enode.Node, connId uint16) *utp.ConnectionId {
	peer := newUtpPeer(dst)
	return utp.NewConnectionId(peer, connId+1, connId)
}

func (z *UtpTransportService) SendId(dst *enode.Node, connId uint16) *utp.ConnectionId {
	peer := newUtpPeer(dst)
	return utp.NewConnectionId(peer, connId, connId+1)
}
