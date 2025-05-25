package history

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/stretchr/testify/require"
	"github.com/zen-eth/shisui/portalwire"
	"github.com/zen-eth/shisui/storage"
)

//go:embed testdata/shanghaibody.txt
var bodyData string

func ContentId(contentKey []byte) []byte {
	digest := sha256.Sum256(contentKey)
	return digest[:]
}

func TestReceiptsAndBody(t *testing.T) {
	entryMap, err := parseDataForBlock()
	require.NoError(t, err)
	testReceiptsAndBody(entryMap, t)
}

func testReceiptsAndBody(entryMap map[string]contentEntry, t *testing.T) {
	historyNetwork, err := genHistoryNetwork(":7893", nil)
	require.NoError(t, err)
	defer func() {
		historyNetwork.Stop()
		historyNetwork.portalProtocol.Utp.Stop()
		historyNetwork.portalProtocol.DiscV5.Close()
	}()

	headerEntry := entryMap["header"]
	// validateContents will store the content
	err = historyNetwork.validateContents([][]byte{headerEntry.key}, [][]byte{headerEntry.value})
	require.NoError(t, err)

	bodyEntry := entryMap["body"]
	err = historyNetwork.validateContents([][]byte{bodyEntry.key}, [][]byte{bodyEntry.value})
	require.NoError(t, err)

	receiptsEntry := entryMap["receipts"]
	err = historyNetwork.validateContents([][]byte{receiptsEntry.key}, [][]byte{receiptsEntry.value})
	require.NoError(t, err)
	// test for portalReceipts encode and decode
	portalReceipts := new(PortalReceipts)
	err = portalReceipts.UnmarshalSSZ(receiptsEntry.value)
	require.NoError(t, err)
	portalBytes, err := portalReceipts.MarshalSSZ()
	require.NoError(t, err)
	require.True(t, bytes.Equal(portalBytes, receiptsEntry.value))
}

func TestPortalBlockShanghai(t *testing.T) {
	bodyBytes, err := hexutil.Decode(bodyData)
	require.NoError(t, err)
	body, err := DecodePortalBlockBodyBytes(bodyBytes)
	require.NoError(t, err)
	require.True(t, len(body.Withdrawals) > 0)
}

func TestGetContentByKey(t *testing.T) {
	historyNetwork1, err := genHistoryNetwork(":7895", nil)
	require.NoError(t, err)
	historyNetwork2, err := genHistoryNetwork(":7896", []*enode.Node{historyNetwork1.portalProtocol.Self()})
	require.NoError(t, err)
	// wait node start
	time.Sleep(10 * time.Second)

	entryMap, err := parseDataForBlock()
	require.NoError(t, err)

	headerEntry := entryMap["header"]

	// test GetBlockHeader
	// no content
	header, err := historyNetwork2.GetBlockHeader(headerEntry.key[1:])
	require.Error(t, err)
	require.Nil(t, header)

	contentId := historyNetwork1.portalProtocol.ToContentId(headerEntry.key)
	err = historyNetwork1.portalProtocol.Put(headerEntry.key, contentId, headerEntry.value)
	require.NoError(t, err)
	// get content from historyNetwork1
	header, err = historyNetwork2.GetBlockHeader(headerEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, header)
	// get content from local
	header, err = historyNetwork2.GetBlockHeader(headerEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, header)

	// test GetBlockBody
	// no content
	bodyEntry := entryMap["body"]
	body, err := historyNetwork2.GetBlockBody(bodyEntry.key[1:])
	require.Error(t, err)
	require.Nil(t, body)

	contentId = historyNetwork1.portalProtocol.ToContentId(bodyEntry.key)
	err = historyNetwork1.portalProtocol.Put(bodyEntry.key, contentId, bodyEntry.value)
	require.NoError(t, err)
	// get content from historyNetwork1
	body, err = historyNetwork2.GetBlockBody(bodyEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, body)
	// get content from local
	body, err = historyNetwork2.GetBlockBody(bodyEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, body)

	// test GetBlockReceipts
	// no content
	receiptsEntry := entryMap["receipts"]
	receipts, err := historyNetwork2.GetReceipts(receiptsEntry.key[1:])
	require.Error(t, err)
	require.Nil(t, receipts)

	contentId = historyNetwork1.portalProtocol.ToContentId(receiptsEntry.key)
	err = historyNetwork1.portalProtocol.Put(receiptsEntry.key, contentId, receiptsEntry.value)
	require.NoError(t, err)
	// get content from historyNetwork1
	receipts, err = historyNetwork2.GetReceipts(receiptsEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, receipts)
	// get content from local
	receipts, err = historyNetwork2.GetReceipts(receiptsEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, receipts)

	if is32Bits() {
		return
	}

	headerNumberEntry := entryMap["headerBlock"]

	// test GetBlockHeader
	// no content
	header, err = historyNetwork2.GetBlockHeader(headerNumberEntry.key[1:])
	require.Error(t, err)
	require.Nil(t, header)

	contentId = historyNetwork1.portalProtocol.ToContentId(headerNumberEntry.key)
	err = historyNetwork1.portalProtocol.Put(headerEntry.key, contentId, headerEntry.value)
	require.NoError(t, err)
	// get content from historyNetwork1
	header, err = historyNetwork2.GetBlockHeader(headerEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, header)
	// get content from local
	header, err = historyNetwork2.GetBlockHeader(headerEntry.key[1:])
	require.NoError(t, err)
	require.NotNil(t, header)
}

type Entry struct {
	ContentKey   string `yaml:"content_key"`
	ContentValue string `yaml:"content_value"`
}

type contentEntry struct {
	key   []byte
	value []byte
}

type MockValidator struct{}

func (m *MockValidator) ValidateContent(contentKey, content []byte) error {
	return nil
}

func genHistoryNetwork(addr string, bootNodes []*enode.Node) (*Network, error) {
	glogger := log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, true))
	slogVerbosity := log.FromLegacyLevel(3)
	glogger.Verbosity(slogVerbosity)
	log.SetDefault(log.NewLogger(glogger))
	conf := portalwire.DefaultPortalProtocolConfig()
	conf.VersionsCacheTTL = 1 * time.Second
	if addr != "" {
		conf.ListenAddr = addr
	}
	if bootNodes != nil {
		conf.BootstrapNodes = bootNodes
	}

	addr1, err := net.ResolveUDPAddr("udp", conf.ListenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr1)
	if err != nil {
		return nil, err
	}

	privKey, err := crypto.GenerateKey()
	if err != nil {
		panic("couldn't generate key: " + err.Error())
	}

	discCfg := discover.Config{
		PrivateKey:  privKey,
		NetRestrict: conf.NetRestrict,
		Bootnodes:   conf.BootstrapNodes,
	}

	nodeDB, err := enode.OpenDB(conf.NodeDBPath)
	if err != nil {
		return nil, err
	}

	localNode := enode.NewLocalNode(nodeDB, privKey)
	localNode.SetFallbackIP(net.IP{127, 0, 0, 1})
	localNode.SetFallbackUDP(addr1.Port)
	localNode.Set(portalwire.Tag)

	discV5, err := discover.ListenV5(conn, localNode, discCfg)
	if err != nil {
		return nil, err
	}

	contentQueue := make(chan *portalwire.ContentElement, 50)
	utpSocket := portalwire.NewZenEthUtp(context.Background(), conf, discV5, conn)
	versionsCache := cache.NewCache[*enode.Node, uint8]().WithMaxKeys(conf.VersionsCacheSize).WithTTL(conf.VersionsCacheTTL)

	portalProtocol, err := portalwire.NewPortalProtocol(conf, portalwire.History, privKey, conn, localNode, discV5, utpSocket, &storage.MockStorage{Db: make(map[string][]byte)}, contentQueue, versionsCache)
	if err != nil {
		return nil, err
	}

	versionsCacheTicker := time.NewTicker(conf.VersionsCacheTTL / 2)
	go func() {
		defer versionsCacheTicker.Stop()
		for {
			select {
			case <-versionsCacheTicker.C:
				versionsCache.DeleteExpired()
			case <-portalProtocol.WaitForClose():
				return
			}
		}
	}()

	err = portalProtocol.Start()
	if err != nil {
		return nil, err
	}

	return NewHistoryNetwork(portalProtocol, &MockValidator{}), nil
}

func parseDataForBlock() (map[string]contentEntry, error) {
	content, err := os.ReadFile("./testdata/block_14764013.json")
	if err != nil {
		return nil, err
	}

	contentMap := make(map[string]map[string]string)
	_ = json.Unmarshal(content, &contentMap)
	res := make(map[string]contentEntry)
	for key, val := range contentMap {
		entry := contentEntry{}
		contentKey := val["content_key"]
		entry.key, err = hexutil.Decode(contentKey)
		if err != nil {
			return nil, err
		}
		entry.value, err = hexutil.Decode(val["content_value"])
		if err != nil {
			return nil, err
		}
		res[key] = entry
	}
	return res, nil
}

func is32Bits() bool {
	return (32 << (^uint(0) >> 63)) == 32
}
