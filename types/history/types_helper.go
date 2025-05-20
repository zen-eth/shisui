package history

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

type HeaderWithProof struct {
	Header *types.Header
	Proof  []byte
}

// DecodeHeaderWithProof return with decoded header
func DecodeHeaderWithProof(content []byte) (*HeaderWithProof, error) {
	headerWithProofBytes, err := DecodeBlockHeaderWithProof(content)
	if err != nil {
		return nil, err
	}
	header, err := DecodeBlockHeader(headerWithProofBytes.Header)
	if err != nil {
		return nil, err
	}
	return &HeaderWithProof{
		Header: header,
		Proof:  headerWithProofBytes.Proof,
	}, nil
}

// DecodeBlockHeaderWithProof return with header rlp bytes
func DecodeBlockHeaderWithProof(content []byte) (*BlockHeaderWithProof, error) {
	headerWithProof := new(BlockHeaderWithProof)
	err := headerWithProof.UnmarshalSSZ(content)
	return headerWithProof, err
}

func DecodeBlockHeader(headerBytes []byte) (*types.Header, error) {
	header := new(types.Header)
	err := rlp.DecodeBytes(headerBytes, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func GetEpochIndex(blockNumber uint64) uint64 {
	return blockNumber / EpochSize
}

func GetEpochIndexByHeader(header types.Header) uint64 {
	return GetEpochIndex(header.Number.Uint64())
}

func GetHeaderRecordIndexByHeader(header types.Header) uint64 {
	return GetHeaderRecordIndex(header.Number.Uint64())
}

func GetHeaderRecordIndex(blockNumber uint64) uint64 {
	return blockNumber % EpochSize
}
