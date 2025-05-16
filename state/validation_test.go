package state

import (
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/stretchr/testify/require"
	"github.com/zen-eth/shisui/types/history"
	"github.com/zen-eth/shisui/validation"
)

var _ validation.Oracle = &MockOracle{}

type MockOracle struct {
	Header *types.Header
}

// GetBlockHeaderByHash implements validation.Oracle.
func (m *MockOracle) GetBlockHeaderByHash(hash []byte) (*types.Header, error) {
	return m.Header, nil
}

// GetHistoricalSummaries implements validation.Oracle.
func (m *MockOracle) GetHistoricalSummaries(epoch uint64) (capella.HistoricalSummaries, error) {
	panic("unimplemented")
}

func TestValidation(t *testing.T) {
	cases, err := getAllTestCase()
	require.NoError(t, err)

	for _, tt := range cases {
		header, err := history.DecodeBlockHeader(hexutil.MustDecode(tt.BlockHeader))
		require.NoError(t, err)
		oracle := &MockOracle{
			Header: header,
		}
		validator := NewStateValidator(oracle)
		err = validator.ValidateContent(hexutil.MustDecode(tt.ContentKey), hexutil.MustDecode(tt.ContentValueOffer))
		require.NoError(t, err)
	}
}

func getAllTestCase() ([]TestCase, error) {
	res := make([]TestCase, 0)
	paths := []string{
		"account_trie_node.yaml",
		"contract_bytecode.yaml",
		"contract_storage_trie_node.yaml",
	}
	for _, path := range paths {
		cases, err := getTestCases(path)
		if err != nil {
			return nil, err
		}
		res = append(res, cases...)
	}
	return res, nil
}
