package portal

import (
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/stretchr/testify/assert"
)

func newLocalNodeForTesting() (*enode.LocalNode, *enode.DB) {
	db, _ := enode.OpenDB("")
	key, _ := crypto.GenerateKey()
	return enode.NewLocalNode(db, key), db
}

func TestDoPortMapping(t *testing.T) {
	timestamp := nowMilliseconds()

	extIP := nat.ExtIP{33, 44, 55, 66}
	localNode, _ := newLocalNodeForTesting()
	listenerAddr := &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1234}

	doPortMapping(extIP, localNode, listenerAddr)

	initialSeq := localNode.Seq()
	if initialSeq < timestamp {
		t.Fatalf("wrong initial seq %d, want at least %d", initialSeq, timestamp)
	}
	assert.Equal(t, localNode.Node().IP(), net.IP{33, 44, 55, 66})
	assert.Equal(t, localNode.Node().UDP(), 1234)
	assert.Equal(t, localNode.Node().TCP(), 0)

	_ = localNode.Node().UDP()
	assert.Equal(t, localNode.Seq(), initialSeq+1)
}

func nowMilliseconds() uint64 {
	ns := time.Now().UnixNano()
	if ns < 0 {
		return 0
	}
	return uint64(ns / 1000 / 1000)
}
