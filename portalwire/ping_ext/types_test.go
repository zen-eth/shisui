package pingext

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/holiman/uint256"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/view"
	"github.com/stretchr/testify/require"
)

var maxUint256 = uint256.MustFromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

func getRadiusBytes() ([]byte, error) {
	radius := uint256.NewInt(0).Sub(maxUint256, uint256.NewInt(1))
	data, err := radius.MarshalSSZ()
	return data, err
}
func Test_ClientInfoAndCapabilitiesPayloadSsz(t *testing.T) {
	testcases := []struct {
		name         string
		clientInfo   string
		radius       *uint256.Int
		capabilities []view.Uint16View
		result       string
	}{
		{
			name:         "has client info",
			clientInfo:   "trin/v0.1.1-b61fdc5c/linux-x86_64/rustc1.81.0",
			radius:       uint256.NewInt(0).Sub(maxUint256, uint256.NewInt(1)),
			capabilities: []view.Uint16View{0, 1, 65535},
			result:       "0x28000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff550000007472696e2f76302e312e312d62363166646335632f6c696e75782d7838365f36342f7275737463312e38312e3000000100ffff",
		},
		{
			name:         "no client info",
			clientInfo:   "",
			radius:       uint256.NewInt(0).Sub(maxUint256, uint256.NewInt(1)),
			capabilities: []view.Uint16View{0, 1, 65535},
			result:       "0x28000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2800000000000100ffff",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := getRadiusBytes()
			require.NoError(t, err)
			payload := &ClientInfoAndCapabilitiesPayload{
				ClientInfo:   []byte(tc.clientInfo),
				DataRadius:   common.Root(data),
				Capabilities: tc.capabilities,
			}
			var buf bytes.Buffer
			err = payload.Serialize(codec.NewEncodingWriter(&buf))
			require.NoError(t, err)
			require.Equal(t, tc.result, hexutil.Encode(buf.Bytes()))
		})
	}
}

func Test_BasicRadiusPayloadSsz(t *testing.T) {
	data, err := getRadiusBytes()
	require.NoError(t, err)
	payload := &BasicRadiusPayload{
		DataRadius: common.Root(data),
	}
	var buf bytes.Buffer
	err = payload.Serialize(codec.NewEncodingWriter(&buf))
	require.NoError(t, err)
	expect := "0xfeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	require.Equal(t, expect, hexutil.Encode(buf.Bytes()))
}

func Test_HistoryRadiusPayloadSsz(t *testing.T) {
	data, err := getRadiusBytes()
	require.NoError(t, err)
	payload := &HistoryRadiusPayload{
		DataRadius:           common.Root(data),
		EphemeralHeaderCount: 4242,
	}
	var buf bytes.Buffer
	err = payload.Serialize(codec.NewEncodingWriter(&buf))
	require.NoError(t, err)
	expect := "0xfeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9210"
	require.Equal(t, expect, hexutil.Encode(buf.Bytes()))
}

func Test_ErrorPayloadSsz(t *testing.T) {
	payload := &ErrorPayload{
		ErrorCode: 2,
		Message:   ErrMessage("hello world"),
	}
	var buf bytes.Buffer
	err := payload.Serialize(codec.NewEncodingWriter(&buf))
	require.NoError(t, err)
	expect := "0x02000600000068656c6c6f20776f726c64"
	require.Equal(t, expect, hexutil.Encode(buf.Bytes()))
}

func TestPreBuildErrorPayload(t *testing.T) {
	testCases := []ErrorPayload{errNotSupportedPayload, errDataNotFoundPayload, errDecodePayload, errSystemErrorPayload}
	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tc.Serialize(codec.NewEncodingWriter(&buf))
		require.NoError(t, err)
		require.Equal(t, errPayloadMap[uint16(tc.ErrorCode)], hexutil.Encode(buf.Bytes()))
	}
}
