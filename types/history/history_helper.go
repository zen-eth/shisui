package history

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

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
	return blockNumber / epochSize
}

func GetEpochIndexByHeader(header types.Header) uint64 {
	return GetEpochIndex(header.Number.Uint64())
}

func GetHeaderRecordIndexByHeader(header types.Header) uint64 {
	return GetHeaderRecordIndex(header.Number.Uint64())
}

func GetHeaderRecordIndex(blockNumber uint64) uint64 {
	return blockNumber % epochSize
}
