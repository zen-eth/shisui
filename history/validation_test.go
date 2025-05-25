package history

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/stretchr/testify/require"
	"github.com/zen-eth/shisui/types/history"
	"github.com/zen-eth/shisui/validation"
	"gopkg.in/yaml.v3"
)

var _ validation.Oracle = &MockOracle{}

type MockOracle struct {
	Header *types.Header
}

// GetFinalizedStateRoot implements validation.Oracle.
func (m *MockOracle) GetFinalizedStateRoot() ([]byte, error) {
	panic("unimplemented")
}

// GetBlockHeaderByHash implements validation.Oracle.
func (m *MockOracle) GetBlockHeaderByHash(hash []byte) (*types.Header, error) {
	return m.Header, nil
}

// GetHistoricalSummaries implements validation.Oracle.
func (m *MockOracle) GetHistoricalSummaries(epoch uint64) (capella.HistoricalSummaries, error) {
	panic("unimplemented")
}

func TestValidateContent(t *testing.T) {
	testData, err := parseTestData()
	require.NoError(t, err)
	for _, data := range testData {
		oracle, err := genMockOracle(data)
		require.NoError(t, err)
		validator := NewHistoryValidator(oracle)
		for _, entry := range data {
			err = validator.ValidateContent(hexutil.MustDecode(entry.ContentKey), hexutil.MustDecode(entry.ContentValue))
			require.NoError(t, err)
		}
	}
}

func parseTestData() ([][]Entry, error) {
	dir := "./testdata/validation"
	res := make([][]Entry, 0)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entries := make([]Entry, 0)
			err = yaml.Unmarshal(data, &entries)
			if err != nil {
				return err
			}
			res = append(res, entries)
		}
		return nil
	})
	return res, err
}

func genMockOracle(data []Entry) (*MockOracle, error) {
	for _, entry := range data {
		key := hexutil.MustDecode(entry.ContentKey)
		if key[0] == 0x00 {
			headWithProof, err := history.DecodeBlockHeaderWithProof(hexutil.MustDecode(entry.ContentValue))
			if err != nil {
				return nil, err
			}
			header, err := history.DecodeBlockHeader(headWithProof.Header)
			if err != nil {
				return nil, err
			}
			return &MockOracle{Header: header}, nil
		}
	}
	return nil, errors.New("no header found")
}
