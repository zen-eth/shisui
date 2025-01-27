package pingext

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/view"
	"github.com/zen-eth/shisui/internal/version"
)

const (
	ClientInfo    uint16 = 0
	BasicRadius   uint16 = 1
	HistoryRadius uint16 = 2
	Error         uint16 = 65535
)

const (
	ErrorNotSupported  uint16 = 0
	ErrorDataNotFound  uint16 = 1
	ErrorDecodePayload uint16 = 2
	ErrorSystemError   uint16 = 3
)

var (
	errNotSupportedPayload = ErrorPayload{
		ErrorCode: 0,
		Message:   ErrMessage("extension is not supported"),
	}
	errDataNotFoundPayload = ErrorPayload{
		ErrorCode: 1,
		Message:   ErrMessage("requested data not found"),
	}
	errDecodePayload = ErrorPayload{
		ErrorCode: 2,
		Message:   ErrMessage("failed to decode payload"),
	}
	errSystemErrorPayload = ErrorPayload{
		ErrorCode: 3,
		Message:   ErrMessage("system error"),
	}
)

var errPayloadMap = map[uint16]string{
	0: "0x000006000000657874656e73696f6e206973206e6f7420737570706f72746564",
	1: "0x0100060000007265717565737465642064617461206e6f7420666f756e64",
	2: "0x0200060000006661696c656420746f206465636f6465207061796c6f6164",
	3: "0x03000600000073797374656d206572726f72",
}

func GetErrorPayloadBytes(code uint16) []byte {
	data, exist := errPayloadMap[code]
	if !exist {
		return []byte{}
	}
	return hexutil.MustDecode(data)
}

type PingExtension interface {
	// check whether support the extension
	IsSupported(ext uint16) bool
	// get all supported extensions
	Extensions() []uint16
}

func NewClientInfoAndCapabilitiesPayload(radius []byte, capabilities []uint16) ClientInfoAndCapabilitiesPayload {
	uint16ViewSlice := make([]view.Uint16View, 0)
	for _, value := range capabilities {
		uint16ViewSlice = append(uint16ViewSlice, view.Uint16View(value))
	}
	return ClientInfoAndCapabilitiesPayload{
		ClientInfo:   ClientInfoBytes(version.ClientInfo()),
		DataRadius:   common.Root(radius),
		Capabilities: uint16ViewSlice,
	}
}

func NewBasicRadiusPayload(data []byte) BasicRadiusPayload {
	return BasicRadiusPayload{
		DataRadius: common.Root(data),
	}
}

func NewHistoryRadiusPayload(radius []byte, count uint16) HistoryRadiusPayload {
	return HistoryRadiusPayload{
		DataRadius:           common.Root(radius),
		EphemeralHeaderCount: view.Uint16View(count),
	}
}

type ClientInfoAndCapabilitiesPayload struct {
	ClientInfo   ClientInfoBytes
	DataRadius   common.Root
	Capabilities CapabilitiesPayload
}

type BasicRadiusPayload struct {
	DataRadius common.Root
}

type HistoryRadiusPayload struct {
	DataRadius           common.Root
	EphemeralHeaderCount view.Uint16View
}

type ErrorPayload struct {
	ErrorCode view.Uint16View
	Message   ErrMessage
}

// ClientInfoAndCapabilitiesPayload
func (client *ClientInfoAndCapabilitiesPayload) Deserialize(dr *codec.DecodingReader) error {
	return dr.Container(&client.ClientInfo, &client.DataRadius, &client.Capabilities)
}

func (client ClientInfoAndCapabilitiesPayload) Serialize(w *codec.EncodingWriter) error {
	return w.Container(&client.ClientInfo, &client.DataRadius, &client.Capabilities)
}

func (client ClientInfoAndCapabilitiesPayload) ByteLength() uint64 {
	return codec.ContainerLength(&client.ClientInfo, &client.DataRadius, &client.Capabilities)
}

func (client *ClientInfoAndCapabilitiesPayload) FixedLength() uint64 {
	return 0
}

func (client ClientInfoAndCapabilitiesPayload) MarshalSSZ() ([]byte, error) {
	var buf bytes.Buffer
	err := client.Serialize(codec.NewEncodingWriter(&buf))
	return buf.Bytes(), err
}

func (client *ClientInfoAndCapabilitiesPayload) UnmarshalSSZ(data []byte) error {
	err := client.Deserialize(codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	return err
}

// BasicRadiusPayload
func (basic *BasicRadiusPayload) Deserialize(dr *codec.DecodingReader) error {
	return dr.FixedLenContainer(&basic.DataRadius)
}

func (basic BasicRadiusPayload) Serialize(w *codec.EncodingWriter) error {
	return w.FixedLenContainer(&basic.DataRadius)
}

func (basic BasicRadiusPayload) ByteLength() uint64 {
	return codec.ContainerLength(&basic.DataRadius)
}

func (basic *BasicRadiusPayload) FixedLength() uint64 {
	return 0
}

func (basic BasicRadiusPayload) MarshalSSZ() ([]byte, error) {
	var buf bytes.Buffer
	err := basic.Serialize(codec.NewEncodingWriter(&buf))
	return buf.Bytes(), err
}

func (basic *BasicRadiusPayload) UnmarshalSSZ(data []byte) error {
	err := basic.Deserialize(codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	return err
}

// HistoryRadiusPayload
func (his *HistoryRadiusPayload) Deserialize(dr *codec.DecodingReader) error {
	return dr.Container(&his.DataRadius, &his.EphemeralHeaderCount)
}

func (his HistoryRadiusPayload) Serialize(w *codec.EncodingWriter) error {
	return w.Container(&his.DataRadius, &his.EphemeralHeaderCount)
}

func (his HistoryRadiusPayload) ByteLength() uint64 {
	return codec.ContainerLength(&his.DataRadius, &his.EphemeralHeaderCount)
}

func (his *HistoryRadiusPayload) FixedLength() uint64 {
	return 0
}

func (his HistoryRadiusPayload) MarshalSSZ() ([]byte, error) {
	var buf bytes.Buffer
	err := his.Serialize(codec.NewEncodingWriter(&buf))
	return buf.Bytes(), err
}

func (his *HistoryRadiusPayload) UnmarshalSSZ(data []byte) error {
	err := his.Deserialize(codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	return err
}

// ErrorPayload
func (ep *ErrorPayload) Deserialize(dr *codec.DecodingReader) error {
	return dr.Container(&ep.ErrorCode, &ep.Message)
}

func (ep ErrorPayload) Serialize(w *codec.EncodingWriter) error {
	return w.Container(&ep.ErrorCode, &ep.Message)
}

func (ep ErrorPayload) ByteLength() uint64 {
	return codec.ContainerLength(&ep.ErrorCode, &ep.Message)
}

func (ep *ErrorPayload) FixedLength() uint64 {
	return 0
}

func (ep ErrorPayload) MarshalSSZ() ([]byte, error) {
	var buf bytes.Buffer
	err := ep.Serialize(codec.NewEncodingWriter(&buf))
	return buf.Bytes(), err
}

func (ep *ErrorPayload) UnmarshalSSZ(data []byte) error {
	err := ep.Deserialize(codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	return err
}
