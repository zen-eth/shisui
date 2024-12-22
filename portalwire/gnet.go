package portalwire

import (
	"context"
	"net"
	"net/netip"
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/panjf2000/gnet/v2"
)

var _ discover.UDPConn = &gnetConn{}

type packet struct {
	n    int
	addr netip.AddrPort
	data []byte
	err  error
}

type gnetConn struct {
	gnet.BuiltinEventEngine
	conn       *net.UDPConn
	log        log.Logger
	localAddr  net.Addr
	eng        gnet.Engine
	packetChan chan packet
	startChan  chan struct{}
}

func NewGnetConn(log log.Logger) *gnetConn {
	return &gnetConn{
		log:        log,
		packetChan: make(chan packet, 1024),
		startChan:  make(chan struct{}),
	}
}

func (gc *gnetConn) ListenUDP(ctx context.Context, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	if udpAddr.IP == nil {
		udpAddr.IP = net.IPv4zero // Use IPv4 0.0.0.0 explicitly
	}
	gc.localAddr = udpAddr

	go func() {
		err := gnet.Run(gc, "udp://"+addr)
		gc.log.Error("gnet run failed", "err", err)
	}()
	<-gc.startChan
	return nil
}

func (gc *gnetConn) OnTraffic(c gnet.Conn) gnet.Action {
	packet := packet{}
	data, err := c.Next(-1)

	if err != nil {
		gc.log.Error("read next failed", "err", err)
		packet.err = err
		gc.packetChan <- packet
		return gnet.None
	}
	// discv5 packet length is 1280 bytes and bigger than 63 bytes
	if len(data) > 1280 || len(data) < 63 {
		gc.log.Error("drop packet with invalid length", "len", len(data), "addr", c.RemoteAddr())
		return gnet.None
	}
	gc.log.Debug("<< reveice data", "remote", c.RemoteAddr())
	dst := make([]byte, len(data))
	copy(dst, data)
	packet.n = len(dst)
	packet.data = dst
	remote := c.RemoteAddr().(*net.UDPAddr)
	packet.addr = netip.AddrPortFrom(
		netip.AddrFrom4([4]byte(remote.IP.To4())),
		uint16(remote.Port),
	)
	gc.packetChan <- packet

	return gnet.None
}

func (gc *gnetConn) OnBoot(eng gnet.Engine) gnet.Action {
	fd, err := eng.Dup()
	if err != nil {
		gc.log.Error("on boot dup failed", "err", err)
		return gnet.Shutdown
	}
	file := os.NewFile(uintptr(fd), "udp")

	conn, err := net.FileConn(file)
	if err != nil {
		gc.log.Error("on boot file conn failed", "err", err)
		return gnet.Shutdown
	}

	udpConn := conn.(*net.UDPConn)
	gc.conn = udpConn
	gc.eng = eng
	gc.startChan <- struct{}{}
	return gnet.None
}

func (gc *gnetConn) OnShutdown(eng gnet.Engine) {
	close(gc.packetChan)
	if err := gc.conn.Close(); err != nil {
		gc.log.Error("on shutdown close failed", "err", err)
	}
}

func (gc *gnetConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	packet := <-gc.packetChan
	copy(b, packet.data)
	return packet.n, packet.addr, packet.err
}

func (gc *gnetConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	gc.log.Debug(">> send data to", "remote", addr)
	return gc.conn.WriteToUDPAddrPort(b, addr)
}

func (gc *gnetConn) Close() error {
	return gc.eng.Stop(context.Background())
}

func (gc *gnetConn) LocalAddr() net.Addr {
	return gc.localAddr
}
