package pingext

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

type ClientInfoAndCapabilitiesPayloadJson struct {
	ClientInfo   string   `json:"clientInfo"`
	DataRadius   string   `json:"dataRadius"`
	Capabilities []uint16 `json:"capabilities"`
}

type BasicRadiusPayloadJson struct {
	DataRadius string `json:"dataRadius"`
}

type HistoryRadiusPayloadJson struct {
	DataRadius           string `json:"dataRadius"`
	EphemeralHeaderCount uint16 `json:"ephemeralHeaderCount"`
}

type ErrPayloadTypeIsNotSupported struct{}

func (p ErrPayloadTypeIsNotSupported) Error() string {
	return "Payload type not supported"
}

func (p ErrPayloadTypeIsNotSupported) ErrorCode() int {
	return -39004
}

type ErrPayloadDecode struct{}

func (p ErrPayloadDecode) Error() string {
	return "Failed to decode payload"
}

func (p ErrPayloadDecode) ErrorCode() int {
	return -39005
}

type ErrPayloadRequired struct{}

func (p ErrPayloadRequired) Error() string {
	return "Payload type is required if payload is specified"
}

func (p ErrPayloadRequired) ErrorCode() int {
	return -39006
}

// parse from json and return the ssz payload
func JsonTypeToSszBytes(payloadType uint16, payload []byte) ([]byte, error) {
	switch payloadType {
	case ClientInfo:
		data := new(ClientInfoAndCapabilitiesPayloadJson)
		err := json.Unmarshal(payload, data)
		if err != nil {
			return nil, ErrPayloadDecode{}
		}
		dataRadius, err := hexutil.Decode(data.DataRadius)
		if err != nil {
			return nil, ErrPayloadDecode{}
		}
		clientInfo := NewClientInfoAndCapabilitiesPayload(dataRadius, data.Capabilities)
		clientInfo.ClientInfo = ClientInfoBytes(data.ClientInfo)
		payloadBytes, err := clientInfo.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		return payloadBytes, nil
	case BasicRadius:
		data := new(BasicRadiusPayloadJson)
		err := json.Unmarshal(payload, data)
		if err != nil {
			return nil, ErrPayloadDecode{}
		}
		dataRadius, err := hexutil.Decode(data.DataRadius)
		if err != nil {
			return nil, ErrPayloadDecode{}
		}
		clientInfo := NewBasicRadiusPayload(dataRadius)
		payloadBytes, err := clientInfo.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		return payloadBytes, nil
	case HistoryRadius:
		data := new(HistoryRadiusPayloadJson)
		err := json.Unmarshal(payload, data)
		if err != nil {
			return nil, ErrPayloadDecode{}
		}
		dataRadius, err := hexutil.Decode(data.DataRadius)
		if err != nil {
			return nil, ErrPayloadDecode{}
		}
		clientInfo := NewHistoryRadiusPayload(dataRadius, data.EphemeralHeaderCount)
		payloadBytes, err := clientInfo.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		return payloadBytes, nil
	default:
		return nil, ErrPayloadTypeIsNotSupported{}
	}
}

func SszBytesToJson(payloadType uint16, payload []byte) (interface{}, error) {
	switch payloadType {
	case ClientInfo:
		clientInfo := new(ClientInfoAndCapabilitiesPayload)
		err := clientInfo.UnmarshalSSZ(payload)
		if err != nil {
			return nil, err
		}
		uint16Slice := make([]uint16, 0)
		for _, value := range clientInfo.Capabilities {
			uint16Slice = append(uint16Slice, uint16(value))
		}
		return ClientInfoAndCapabilitiesPayloadJson{
			ClientInfo:   string(clientInfo.ClientInfo),
			DataRadius:   hexutil.Encode(clientInfo.DataRadius[:]),
			Capabilities: uint16Slice,
		}, nil
	case BasicRadius:
		clientInfo := new(BasicRadiusPayload)
		err := clientInfo.UnmarshalSSZ(payload)
		if err != nil {
			return nil, err
		}
		return BasicRadiusPayloadJson{
			DataRadius: hexutil.Encode(clientInfo.DataRadius[:]),
		}, nil
	case HistoryRadius:
		clientInfo := new(HistoryRadiusPayload)
		err := clientInfo.UnmarshalSSZ(payload)
		if err != nil {
			return nil, err
		}
		return HistoryRadiusPayloadJson{
			DataRadius:           hexutil.Encode(clientInfo.DataRadius[:]),
			EphemeralHeaderCount: uint16(clientInfo.EphemeralHeaderCount),
		}, nil
	default:
		return nil, ErrPayloadTypeIsNotSupported{}
	}
}

func GetDataRadiusByType(payloadType uint16, payload []byte) ([]byte, error) {
	switch payloadType {
	case ClientInfo:
		clientInfo := new(ClientInfoAndCapabilitiesPayload)
		err := clientInfo.UnmarshalSSZ(payload)
		if err != nil {
			return nil, err
		}
		return clientInfo.DataRadius[:], nil
	case BasicRadius:
		clientInfo := new(BasicRadiusPayload)
		err := clientInfo.UnmarshalSSZ(payload)
		if err != nil {
			return nil, err
		}
		return clientInfo.DataRadius[:], nil
	case HistoryRadius:
		clientInfo := new(HistoryRadiusPayload)
		err := clientInfo.UnmarshalSSZ(payload)
		if err != nil {
			return nil, err
		}
		return clientInfo.DataRadius[:], nil
	default:
		return nil, ErrPayloadTypeIsNotSupported{}
	}
}
