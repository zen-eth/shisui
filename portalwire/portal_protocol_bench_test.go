package portalwire

//import (
//	"bytes"
//	"context"
//	"fmt"
//	"github.com/aws/smithy-go/rand"
//	"github.com/ethereum/go-ethereum/log"
//	"github.com/ethereum/go-ethereum/p2p/enode"
//	assert "github.com/stretchr/testify/require"
//	"github.com/zen-eth/shisui/testlog"
//	utp "github.com/zen-eth/utp-go"
//	"io"
//	"net/http"
//	"os"
//	"runtime/pprof"
//	"runtime/trace"
//	"sync"
//	"testing"
//	"time"
//
//	"github.com/felixge/fgprof"
//	_ "net/http/pprof"
//)
//
//const (
//	test_socket_data_len = 1_000_000
//	num_transfers        = 500
//)
//
//func TestBenchmarkUtpWithDiscv5(t *testing.T) {
//	http.DefaultServeMux.Handle("/debug/fgprof", fgprof.Handler())
//	go func() {
//		addr := "localhost:6060"
//		log.Info(http.ListenAndServe(addr, nil).Error())
//	}()
//
//	// 设置最大线程数为CPU核心数
//
//	go func() {
//		traceFile, _ := os.Create("concurrency_trace_trin_bench.prof")
//		time.Sleep(15 * time.Second)
//		_ = trace.Start(traceFile)
//	}()
//	defer trace.Stop()
//	//
//	//// // CPU 分析
//	go func() {
//		cpuFile, _ := os.Create("concurrency_cpu.prof")
//		time.Sleep(15 * time.Second)
//		_ = pprof.StartCPUProfile(cpuFile)
//	}()
//	defer pprof.StopCPUProfile()
//
//	memFile, _ := os.Create("concurrency_mem.prof")
//	defer pprof.WriteHeapProfile(memFile)
//
//	node1, err := setupLocalPortalNode(t, "0.0.0.0:3321", nil, DefaultUtpConnSize*10, 1)
//	assert.NoError(t, err)
//	node1.Log = testlog.Logger(t, log.LevelError)
//	err = node1.Start()
//	assert.NoError(t, err)
//	defer stopNode(node1)
//
//	//discLogLvl = log.LevelError
//	node2, err := setupLocalPortalNode(t, "0.0.0.0:3322", []*enode.Node{node1.localNode.Node()}, DefaultUtpConnSize*10, 1)
//	assert.NoError(t, err)
//	node2.Log = testlog.Logger(t, log.LevelError)
//	err = node2.Start()
//	assert.NoError(t, err)
//	defer stopNode(node2)
//
//	time.Sleep(8 * time.Second)
//
//	_, err = node1.ping(node2.localNode.Node())
//	assert.NoError(t, err)
//
//	data := make([]byte, test_socket_data_len)
//	_, _ = io.ReadFull(rand.Reader, data)
//
//	ctx := context.Background()
//	var wg sync.WaitGroup
//	start := time.Now()
//	for i := 0; i < num_transfers; i++ {
//		wg.Add(2)
//		initiateTransfer(t, ctx, uint16(i*2), node1.Utp, node2.Utp, data, &wg)
//	}
//
//	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
//	go func() {
//		// Wait for all transfers in a separate goroutine
//		wg.Wait()
//		cancel()
//	}()
//	<-timeoutCtx.Done()
//	assert.ErrorIs(t, timeoutCtx.Err(), context.Canceled, "Timed out waiting for transfer to complete")
//
//	elapsed := time.Since(start)
//	megabitsSent := float64(num_transfers) * float64(test_socket_data_len) * 8.0 / 1_000_000.0
//	transferRate := megabitsSent / elapsed.Seconds()
//
//	t.Logf("finished high concurrency load test of %d simultaneous transfers, in %v, at a rate of %.0f Mbps",
//		num_transfers, elapsed, transferRate)
//}
//
//func initiateTransfer(t *testing.T, ctx context.Context, i uint16, sender *UtpTransportService, receiver *UtpTransportService, data []byte, wg *sync.WaitGroup) {
//	initiatorCid := uint16(100) + i
//	responderCid := uint16(100) + i + 1
//
//	recvCid := utp.NewConnectionId(newUtpPeer(sender.discV5.Self()), responderCid, initiatorCid)
//	//sendCid := utp.NewConnectionId(newUtpPeer(receiver.discV5.Self()), initiatorCid, responderCid)
//
//	// Start receiver goroutine
//	go func() {
//		defer func() {
//			t.Log("recv wg done")
//			wg.Done()
//		}()
//		stream, err := receiver.AcceptWithCid(ctx, recvCid)
//		if err != nil {
//			panic(fmt.Errorf("accept failed: %w", err))
//		}
//
//		buf := make([]byte, 0)
//		n, err := stream.ReadToEOF(ctx, &buf)
//		assert.NoError(t, err, "CID send=%d recv=%d read to eof error: %v",
//			recvCid.Send, recvCid.Recv, err)
//
//		t.Logf("CID send=%d recv=%d read %d bytes from uTP stream",
//			recvCid.Send, recvCid.Recv, n)
//		assert.Equal(t, len(data), n,
//			"received wrong number of bytes: got %d, want %d", n, len(data))
//		assert.True(t, bytes.Equal(data, buf),
//			"received data doesn't match sent data")
//		stream.Close()
//	}()
//
//	// Start sender goroutine
//	go func() {
//		defer func() {
//			t.Log("writer wg done")
//			wg.Done()
//		}()
//		stream, err := sender.DialWithCid(ctx, receiver.discV5.Self(), initiatorCid)
//		assert.NoError(t, err, "connect failed: %w", err)
//		assert.NotNil(t, stream, "stream should not be nil")
//		n, err := stream.Write(ctx, data)
//		assert.NoError(t, err, "write failed: %w", err)
//
//		assert.Equal(t, len(data), n,
//			"sent wrong number of bytes: got %d, want %d", n, len(data))
//		stream.Close()
//	}()
//}
