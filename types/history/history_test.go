package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/view"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type Entry struct {
	ContentKey   string `yaml:"content_key"`
	ContentValue string `yaml:"content_value"`
}

func ContentId(contentKey []byte) []byte {
	digest := sha256.Sum256(contentKey)
	return digest[:]
}

// testcases from https://github.com/ethereum/portal-network-specs/blob/master/content-keys-test-vectors.md
func TestContentKey(t *testing.T) {
	testCases := []struct {
		name          string
		hash          string
		contentKey    string
		contentIdHex  string
		contentIdU256 string
		selector      ContentType
	}{
		{
			name:          "block header key",
			hash:          "d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d",
			contentKey:    "00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d",
			contentIdHex:  "3e86b3767b57402ea72e369ae0496ce47cc15be685bec3b4726b9f316e3895fe",
			contentIdU256: "28281392725701906550238743427348001871342819822834514257505083923073246729726",
			selector:      BlockHeaderType,
		},
		{
			name:          "block body key",
			hash:          "d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d",
			contentKey:    "01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d",
			contentIdHex:  "ebe414854629d60c58ddd5bf60fd72e41760a5f7a463fdcb169f13ee4a26786b",
			contentIdU256: "106696502175825986237944249828698290888857178633945273402044845898673345165419",
			selector:      BlockBodyType,
		},
		{
			name:          "receipt key",
			hash:          "d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d",
			contentKey:    "02d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d",
			contentIdHex:  "a888f4aafe9109d495ac4d4774a6277c1ada42035e3da5e10a04cc93247c04a4",
			contentIdU256: "76230538398907151249589044529104962263309222250374376758768131420767496438948",
			selector:      ReceiptsType,
		},
	}

	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			hashByte, err := hex.DecodeString(c.hash)
			require.NoError(t, err)

			contentKey := NewContentKey(c.selector, hashByte).Encode()
			hexKey := hex.EncodeToString(contentKey)
			require.Equal(t, hexKey, c.contentKey)
			contentId := ContentId(contentKey)
			require.Equal(t, c.contentIdHex, hex.EncodeToString(contentId))

			bigNum := big.NewInt(0).SetBytes(contentId)
			u256Format, isOverflow := uint256.FromBig(bigNum)
			require.False(t, isOverflow)
			u256Str := fmt.Sprint(u256Format)
			require.Equal(t, u256Str, c.contentIdU256)
		})
	}
}

func TestBlockNumber(t *testing.T) {
	blockNumber := 12345678
	contentKey := "0x034e61bc0000000000"
	contentId := "0x2113990747a85ab39785d21342fa5db1f68acc0011605c0c73f68fc331643dcf"
	contentIdU256 := "14960950260935695396511307566164035182676768442501235074589175304147024756175"

	key := view.Uint64View(blockNumber)
	var buf bytes.Buffer
	err := key.Serialize(codec.NewEncodingWriter(&buf))
	require.NoError(t, err)
	keyData := []byte{byte(BlockHeaderNumberType)}
	keyData = append(keyData, buf.Bytes()...)
	require.Equal(t, hexutil.MustDecode(contentKey), keyData)

	contentIdData := ContentId(keyData)
	require.Equal(t, contentId, hexutil.Encode(contentIdData))

	bigNum := big.NewInt(0).SetBytes(contentIdData)
	u256Format, isOverflow := uint256.FromBig(bigNum)
	require.False(t, isOverflow)
	u256Str := fmt.Sprint(u256Format)
	require.Equal(t, u256Str, contentIdU256)
}

func TestHeaderWithProof(t *testing.T) {
	file, err := os.ReadFile("./testdata/header_with_proof.yaml")
	require.NoError(t, err)
	entries := make([]Entry, 0)
	err = yaml.Unmarshal(file, &entries)
	require.NoError(t, err)
	for _, item := range entries {
		keyBytes := hexutil.MustDecode(item.ContentKey)
		// get the header with proof
		if keyBytes[0] != 0 {
			continue
		}
		headerWithProof := new(BlockHeaderWithProof)
		err := headerWithProof.UnmarshalSSZ(hexutil.MustDecode(item.ContentValue))
		require.NoError(t, err)
		header := new(types.Header)
		err = rlp.DecodeBytes(headerWithProof.Header, header)
		require.NoError(t, err)
		if header.Number.Uint64() >= cancunNumber {
			proof := new(BlockProofHistoricalSummariesDeneb)
			err = proof.UnmarshalSSZ(headerWithProof.Proof[:])
			require.NoError(t, err)
		} else if header.Number.Uint64() >= shanghaiBlockNumber {
			proof := new(BlockProofHistoricalSummariesCapella)
			err = proof.UnmarshalSSZ(headerWithProof.Proof[:])
			require.NoError(t, err)
		} else if header.Number.Uint64() >= mergeBlockNumber {
			proof := new(BlockProofHistoricalRoots)
			err = proof.UnmarshalSSZ(headerWithProof.Proof[:])
			require.NoError(t, err)
		} else {
			proof := new(BlockProofHistoricalHashesAccumulator)
			err = proof.UnmarshalSSZ(headerWithProof.Proof[:])
			require.NoError(t, err)
		}
	}
}

func TestEphemeralType(t *testing.T) {
	entry := Entry{
		ContentKey:   "0xd24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f27618301",
		ContentValue: "0x0800000063020000f90258a0b390d63aac03bbef75de888d16bd56b91c9291c2a7e38d36ac24731351522bd1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a068421c2c599dc31396a09772a073fb421c4bd25ef1462914ef13e5dfa2d31c23a0f0280ae7fd02f2b9684be8d740830710cd62e4869c891c3a0ead32ea757e70a3a0b39f9f7a13a342751bd2c575eca303e224393d4e11d715866b114b7e824da608b9010094a9480614840b245a1a2148e2100e2070472151b44c3020280930809a20c011609520bc10080074a61c782411e34713ee19c560ca02208f4770080013bc5d302d84743dd0008c5d089d5b1c95940de80809888ba7ed68512d426c048934c8cc0a08dd440b461265001ee50909a26d0213000a7411242c72a648c87e104c0097a0aaba477628508533c5924867341dd11305aa372350b019244034dc849419968b00fd2dda39ecff042639c43923f0d48495d2a40468524bce13a86444c82071ca9c431208870b33f5320f680f3991c2349e2433c80440b0832016820e1070a4405aadcc40050a5006c24504f0098c4391e0f04047c824d1d88ca8021d240510808401312d008401c9c38083a9371c84665ba27f8f6265617665726275696c642e6f7267a085175443c2889afcb52288e0fa8804b671e582f9fd416071a70642d90c7dc0db88000000000000000085012643ff14a0f0747de0368fb967ede9b81320a5b01a4d85b3d427e8bc8e96ff371478d80e768302000080a0ec0befcffe8b2792fc5e7b67dac85ee3bbb09bc56b0ea5d9a698ec3b402d296ff9025ba00d599f184bf4f978eb6f046eb0365b82ca9cb93e999dea93033556751707278ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a07c77f711a2cb5c59fcc78d63f59dbf73a7fe69be3cad9d8220f9e64668a100eda0bed93e45262811ab648db2f41f3e43706d6ed0bfc9c09d30322e0d8c342657e8a0488fe820ca9e0ec9eb5006e55927151e29219c0709df152de872dfa7c89253f0b90100856931400a4b0f6f3aaaf091e2a05ad131c309001e2308908695014650224020b39105bf5a000230125333205ddf25268379af26ea51e9318666b56d43ef980b9834d708d3001b3bd82660ef8a76e928a0711385d46c4e7d00930e38f93c8100182221870217552690dcf09019316ccd2d31026911cdf436d61a4e3a7c2b40f46c0426d4a80c47022171f9c80625105ed801bf21ef0029297166606de1f18d3902860561e609e485474353cc2b0f2d4b9c2148a5c62513007f358127d080ca601dc28e16141a05786d209d845b8d04c600746e5fb40912b801044386527be54c2172ec46061c0740098c0b8cfc6d35060718d9aa490ce7d68905818070b1979d808401312cff8401c9c38083cc573d84665ba2738f6265617665726275696c642e6f7267a0d735fec5f0cefaf3aba227590a5b0f8ab52e1a6f6a3044d064ad132de188b8b988000000000000000085012a435d21a046d0c52945253f0084ee5f6d57e093b946cabcb415006fd3dfdbb3b797f8eb2f8304000083020000a0777b0eec9bf4a5496c56b87a64e41b89f8ff58e3feb9f611b0afeb34a263e920",
	}

	key := &FindContentEphemeralHeadersKey{}
	err := key.UnmarshalSSZ(hexutil.MustDecode(entry.ContentKey))
	require.NoError(t, err)

	keyBytes, err := key.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, hexutil.Encode(keyBytes), entry.ContentKey)

	val := &EphemeralHeaderPayload{}
	err = val.UnmarshalSSZ(hexutil.MustDecode(entry.ContentValue))
	require.NoError(t, err)

	valBytes, err := val.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, hexutil.Encode(valBytes), entry.ContentValue)

	entry = Entry{
		ContentKey:   "0xd24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183",
		ContentValue: "0x04000000f90258a0b390d63aac03bbef75de888d16bd56b91c9291c2a7e38d36ac24731351522bd1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495222290dd7278aa3ddd389cc1e1d165cc4bafe5a068421c2c599dc31396a09772a073fb421c4bd25ef1462914ef13e5dfa2d31c23a0f0280ae7fd02f2b9684be8d740830710cd62e4869c891c3a0ead32ea757e70a3a0b39f9f7a13a342751bd2c575eca303e224393d4e11d715866b114b7e824da608b9010094a9480614840b245a1a2148e2100e2070472151b44c3020280930809a20c011609520bc10080074a61c782411e34713ee19c560ca02208f4770080013bc5d302d84743dd0008c5d089d5b1c95940de80809888ba7ed68512d426c048934c8cc0a08dd440b461265001ee50909a26d0213000a7411242c72a648c87e104c0097a0aaba477628508533c5924867341dd11305aa372350b019244034dc849419968b00fd2dda39ecff042639c43923f0d48495d2a40468524bce13a86444c82071ca9c431208870b33f5320f680f3991c2349e2433c80440b0832016820e1070a4405aadcc40050a5006c24504f0098c4391e0f04047c824d1d88ca8021d240510808401312d008401c9c38083a9371c84665ba27f8f6265617665726275696c642e6f7267a085175443c2889afcb52288e0fa8804b671e582f9fd416071a70642d90c7dc0db88000000000000000085012643ff14a0f0747de0368fb967ede9b81320a5b01a4d85b3d427e8bc8e96ff371478d80e768302000080a0ec0befcffe8b2792fc5e7b67dac85ee3bbb09bc56b0ea5d9a698ec3b402d296f",
	}

	key2 := &OfferEphemeralHeaderKey{}
	err = key2.UnmarshalSSZ(hexutil.MustDecode(entry.ContentKey))
	require.NoError(t, err)

	keyBytes, err = key2.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, hexutil.Encode(keyBytes), entry.ContentKey)

	val2 := &OfferEphemeralHeader{}
	err = val2.UnmarshalSSZ(hexutil.MustDecode(entry.ContentValue))
	require.NoError(t, err)

	valBytes, err = val2.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, hexutil.Encode(valBytes), entry.ContentValue)
}
