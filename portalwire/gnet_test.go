package portalwire

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/ethereum/go-ethereum/log"
	"github.com/stretchr/testify/assert"
)

func genGnetConn(addr string) (*gnetConn, error) {
	logger := log.New()
	gc := NewGnetConn(logger)
	err := gc.ListenUDP(context.Background(), addr)
	return gc, err
}

func udpAddrToAddrPort(udpAddr *net.UDPAddr) (netip.AddrPort, error) {
	// Parse the IP to netip.Addr
	addr, err := netip.ParseAddr(udpAddr.IP.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse IP: %w", err)
	}

	// Combine the address and port
	return netip.AddrPortFrom(addr, uint16(udpAddr.Port)), nil
}

func TestGnetConn_BasicOperations(t *testing.T) {
	conn1, err := genGnetConn(":12345")
	assert.NoError(t, err)
	defer conn1.Close()

	conn2, err := genGnetConn(":12346")
	assert.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.localAddr.(*net.UDPAddr)
	addr2 := conn2.localAddr.(*net.UDPAddr)

	netipAddr1, err := udpAddrToAddrPort(addr1)
	if err != nil {
		t.Fatal(err)
	}

	netipAddr2, err := udpAddrToAddrPort(addr2)
	if err != nil {
		t.Fatal(err)
	}
	sendData := []byte("Hello, UDP! Hello, UDP! Hello, UDP! Hello, UDP! Hello, UDP! Hello, UDP! Hello, UDP! Hello, UDP!")
	conn1.conn.WriteToUDPAddrPort(sendData, netipAddr2)
	buf := make([]byte, 1280)
	n, _, err := conn2.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, buf[:n], sendData)

	conn2.conn.WriteToUDPAddrPort(sendData, netipAddr1)
	buf = make([]byte, 1280)
	n, _, err = conn1.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, buf[:n], sendData)
}
