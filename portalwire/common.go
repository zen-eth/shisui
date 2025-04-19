// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package portalwire

import (
	"bytes"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/tetratelabs/wabin/leb128"
)

// UDPConn is a network connection on which discovery can operate.
type UDPConn interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// Config holds settings for the discovery listener.
type Config struct {
	// These settings are required and configure the UDP listener:
	PrivateKey *ecdsa.PrivateKey

	// All remaining settings are optional.

	// Packet handling configuration:
	NetRestrict *netutil.Netlist  // list of allowed IP networks
	Unhandled   chan<- ReadPacket // unhandled packets are sent on this channel

	// Node table configuration:
	Bootnodes               []*enode.Node // list of bootstrap nodes
	PingInterval            time.Duration // speed of node liveness check
	RefreshInterval         time.Duration // used in bucket refresh
	NoFindnodeLivenessCheck bool          // turns off validation of table nodes in FINDNODE handler
	DisableInitCheck        bool          // disables init check in table

	// The options below are useful in very specific cases, like in unit tests.
	V5ProtocolID *[6]byte
	Log          log.Logger         // if set, log messages go here
	ValidSchemes enr.IdentityScheme // allowed identity schemes
	Clock        mclock.Clock
}

func (cfg Config) withDefaults() Config {
	// Node table configuration:
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 3 * time.Second
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Minute
	}

	// Debug/test settings:
	if cfg.Log == nil {
		cfg.Log = log.Root()
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{}
	}
	return cfg
}

// ReadPacket is a packet that couldn't be handled. Those packets are sent to the unhandled
// channel if configured.
type ReadPacket struct {
	Data []byte
	Addr netip.AddrPort
}

type randomSource interface {
	Intn(int) int
	Int63n(int64) int64
	Shuffle(int, func(int, int))
}

// reseedingRandom is a random number generator that tracks when it was last re-seeded.
type reseedingRandom struct {
	mu  sync.Mutex
	cur *rand.Rand
}

func (r *reseedingRandom) seed() {
	var b [8]byte
	_, _ = crand.Read(b[:])
	seed := binary.BigEndian.Uint64(b[:])
	new := rand.New(rand.NewSource(int64(seed)))

	r.mu.Lock()
	r.cur = new
	r.mu.Unlock()
}

func (r *reseedingRandom) Intn(n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur.Intn(n)
}

func (r *reseedingRandom) Int63n(n int64) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur.Int63n(n)
}

func (r *reseedingRandom) Shuffle(n int, swap func(i, j int)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur.Shuffle(n, swap)
}

func encodeSingleContent(data []byte) []byte {
	contentLen := uint32(len(data))
	contentLenBytes := leb128.EncodeUint32(contentLen)
	return append(contentLenBytes, data...)
}

func decodeSingleContent(data []byte) (content []byte, remaining []byte, err error) {
	reader := bytes.NewReader(data)
	contentLen, bytesRead, err := leb128.DecodeUint32(reader)
	if err != nil {
		return nil, data, err
	}

	headerSize := int(bytesRead)
	if len(data) < headerSize+int(contentLen) {
		return nil, data, errors.New("insufficient data for content length")
	}

	content = data[headerSize : headerSize+int(contentLen)]
	remaining = data[headerSize+int(contentLen):]
	return content, remaining, nil
}
