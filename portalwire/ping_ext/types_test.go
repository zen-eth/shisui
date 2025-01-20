package pingext

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/view"
	"github.com/stretchr/testify/require"
)

func Test_ClientInfoAndCapabilitiesPayloadSsz(t *testing.T) {
	payload := &ClientInfoAndCapabilitiesPayload{
		ClientInfo: []byte("trin/v0.1.1-b61fdc5c/linux-x86_64/rustc1.81.0"),
		DataRadius: common.Root(hexutil.MustDecode("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")),
		Capabilities: []view.Uint16View{0, 1, 65535},
	}
	var buf bytes.Buffer
	err := payload.Serialize(codec.NewEncodingWriter(&buf))
	require.NoError(t, err)
	t.Log(buf)
}