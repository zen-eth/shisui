package pingext

import (
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/view"
)

const (
	CustomPayloadExtensionsFormatPayloadLimit = 1100
	MaxClientInfoByteLength = 200
	MaxCapabilitiesLength = 400
	MaxErrorByteLength = 300
)

type CustomPayloadExtensionsFormatPayload []byte

func (cus *CustomPayloadExtensionsFormatPayload) Deserialize(dr *codec.DecodingReader) error {
	return dr.ByteList((*[]byte)(cus), uint64(CustomPayloadExtensionsFormatPayloadLimit))
}

func (cus CustomPayloadExtensionsFormatPayload) Serialize(w *codec.EncodingWriter) error {
	return w.Write(cus)
}

func (cus CustomPayloadExtensionsFormatPayload) ByteLength() (out uint64) {
	return uint64(len(cus))
}

func (cus *CustomPayloadExtensionsFormatPayload) FixedLength() uint64 {
	return 0
}

type ClientInfoBytes []byte

func (ci *ClientInfoBytes) Deserialize(dr *codec.DecodingReader) error {
	return dr.ByteList((*[]byte)(ci), uint64(MaxClientInfoByteLength))
}

func (ci ClientInfoBytes) Serialize(w *codec.EncodingWriter) error {
	return w.Write(ci)
}

func (ci ClientInfoBytes) ByteLength() (out uint64) {
	return uint64(len(ci))
}

func (ci *ClientInfoBytes) FixedLength() uint64 {
	return 0
}

type CapabilitiesPayload []view.Uint16View


func (c *CapabilitiesPayload) Deserialize(dr *codec.DecodingReader) error {
	return dr.List(func() codec.Deserializable {
		i := len(*c)
		*c = append(*c, view.Uint16View(0))
		return &(*c)[i]
	}, uint64(view.Uint16Type.TypeByteLength()), uint64(MaxCapabilitiesLength))
}

func (c CapabilitiesPayload) Serialize(w *codec.EncodingWriter) error {
	return w.List(func(i uint64) codec.Serializable {
		return &c[i]
	}, view.Uint16Type.TypeByteLength(), uint64(len(c)))
}

func (c CapabilitiesPayload) ByteLength() (out uint64) {
	return uint64(len(c)) * view.Uint16Type.TypeByteLength()
}

func (c *CapabilitiesPayload) FixedLength() uint64 {
	return 0
}

type ErrMessage []byte

func (em *ErrMessage) Deserialize(dr *codec.DecodingReader) error {
	return dr.ByteList((*[]byte)(em), uint64(MaxErrorByteLength))
}

func (em ErrMessage) Serialize(w *codec.EncodingWriter) error {
	return w.Write(em)
}

func (em ErrMessage) ByteLength() (out uint64) {
	return uint64(len(em))
}

func (em *ErrMessage) FixedLength() uint64 {
	return 0
}