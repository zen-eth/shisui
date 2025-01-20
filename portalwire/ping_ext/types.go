package pingext

import (
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/view"
)

const (
	ClientInfo uint16 = 0
	BasicRadius uint16 = 1
	HistoryRadius uint16 = 2
	Error uint16 = 65535
)

const (
	ErrorNotSupported uint16 = 0
	ErrorDataNotFound uint16 = 1
	ErrorDecodePayload uint16 = 2
	ErrorSystemError uint16 = 3
)

type CustomPayloadExtensionsFormat struct {
	Type view.Uint16View
	Payload CustomPayloadExtensionsFormatPayload
}

type ClientInfoAndCapabilitiesPayload struct {
	ClientInfo ClientInfoBytes
	DataRadius common.Root
	Capabilities CapabilitiesPayload
}

type HistoryRadiusPayload struct {
	DataRadius common.Root
	EphemeralHeaderCount view.Uint16View
}

type ErrorPayload struct {
	ErrorCode view.Uint16View
	Message ErrMessage
}

// CustomPayloadExtensionsFormat
func (h *CustomPayloadExtensionsFormat) Deserialize(dr *codec.DecodingReader) error {
	return dr.Container(&h.Type, &h.Payload)
}

func (h CustomPayloadExtensionsFormat) Serialize(w *codec.EncodingWriter) error {
	return w.Container(&h.Type, &h.Payload)
}

func (h CustomPayloadExtensionsFormat) ByteLength() uint64 {
	return codec.ContainerLength(&h.Type, &h.Payload)
}

func (h *CustomPayloadExtensionsFormat) FixedLength() uint64 {
	return 0
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
