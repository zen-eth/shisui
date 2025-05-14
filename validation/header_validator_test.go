package validation

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/codec"
	"github.com/stretchr/testify/require"
	"github.com/zen-eth/shisui/types/history"
	"gopkg.in/yaml.v3"
)

func TestPreMergeHeader(t *testing.T) {
	validator := NewHeaderValidatorWithOracle(nil)
	entries, err := parsePreMergeData()
	require.NoError(t, err)
	for _, entry := range entries {
		headerWithProof, err := history.DecodeBlockHeaderWithProof(entry.value)
		require.NoError(t, err)
		err = validator.ValidateHeaderWithProof(headerWithProof)
		require.NoError(t, err)
	}
}

func TestMergeToCapellaHeader(t *testing.T) {
	validator := NewHeaderValidatorWithOracle(nil)
	entries, err := parseBeaconBlockProof("./testdata/block_proofs_bellatrix")
	require.NoError(t, err)
	for _, entry := range entries {
		proof := entry.ToBellatrixProof()
		err = validator.validateMergeToCapellaHeader(entry.GetExecutionBlockHeader(), proof)
		require.NoError(t, err)
	}
}

func TestCapellaToDenebHeader(t *testing.T) {
	summaries, err := parseHistorySummaries()
	require.NoError(t, err)
	validator := NewHeaderValidatorWithHistorySummaries(summaries)
	entries, err := parseBeaconBlockProof("./testdata/block_proofs_capella")
	require.NoError(t, err)
	for _, entry := range entries {
		proof := entry.ToCapellaProof()
		err = validator.validateCapellaToDenebHeader(entry.GetExecutionBlockHeader(), proof)
		require.NoError(t, err)
	}
}

func TestPostDenebHeader(t *testing.T) {
	summaries, err := parseHistorySummaries()
	require.NoError(t, err)
	validator := NewHeaderValidatorWithHistorySummaries(summaries)
	entries, err := parseBeaconBlockProof("./testdata/block_proofs_deneb")
	require.NoError(t, err)
	for _, entry := range entries {
		proof := entry.ToPostDenebProof()
		err = validator.validatePostDenebHeader(entry.GetExecutionBlockHeader(), proof)
		require.NoError(t, err)
	}
}

type contentEntry struct {
	key   []byte
	value []byte
}

func parsePreMergeData() ([]contentEntry, error) {
	headWithProofBytes, err := os.ReadFile("./testdata/header_with_proofs.json")
	if err != nil {
		return nil, err
	}
	headerMap := make(map[string]map[string]string)

	err = json.Unmarshal(headWithProofBytes, &headerMap)
	if err != nil {
		return nil, err
	}
	res := make([]contentEntry, 0)
	for _, v := range headerMap {
		entry := contentEntry{}
		val := v["value"]
		bytes, err := hexutil.Decode(val)
		if err != nil {
			return nil, err
		}
		entry.value = bytes
		key := v["content_key"]
		keyBytes, err := hexutil.Decode(key)
		if err != nil {
			return nil, err
		}
		entry.key = keyBytes
		res = append(res, entry)
	}
	return res, nil
}

type beaconBlockProof struct {
	ExecutionBlockHeader string   `yaml:"execution_block_header"`
	ExecutionBlockProof  []string `yaml:"execution_block_proof"`
	BeaconBlockRoot      string   `yaml:"beacon_block_root"`
	BeaconBlockProof     []string `yaml:"beacon_block_proof"`
	Slot                 uint64   `yaml:"slot"`
}

func (b beaconBlockProof) GetExecutionBlockHeader() []byte {
	return hexutil.MustDecode(b.ExecutionBlockHeader)
}

func (b beaconBlockProof) GetBeaconBlockRoot() []byte {
	return hexutil.MustDecode(b.BeaconBlockRoot)
}

func (b beaconBlockProof) GetExecutionBlockProof() [][]byte {
	res := make([][]byte, 0)
	for _, proof := range b.ExecutionBlockProof {
		res = append(res, hexutil.MustDecode(proof))
	}
	return res
}

func (b beaconBlockProof) GetBeaconBlockProof() [][]byte {
	res := make([][]byte, 0)
	for _, proof := range b.BeaconBlockProof {
		res = append(res, hexutil.MustDecode(proof))
	}
	return res
}

func (b beaconBlockProof) ToPostDenebProof() *history.BlockProofHistoricalSummariesDeneb {
	return &history.BlockProofHistoricalSummariesDeneb{
		BeaconBlockProof:    b.GetBeaconBlockProof(),
		BeaconBlockRoot:     b.GetBeaconBlockRoot(),
		ExecutionBlockProof: b.GetExecutionBlockProof(),
		Slot:                b.Slot,
	}
}
func (b beaconBlockProof) ToCapellaProof() *history.BlockProofHistoricalSummariesCapella {
	return &history.BlockProofHistoricalSummariesCapella{
		BeaconBlockProof:    b.GetBeaconBlockProof(),
		BeaconBlockRoot:     b.GetBeaconBlockRoot(),
		ExecutionBlockProof: b.GetExecutionBlockProof(),
		Slot:                b.Slot,
	}
}
func (b beaconBlockProof) ToBellatrixProof() *history.BlockProofHistoricalRoots {
	return &history.BlockProofHistoricalRoots{
		BeaconBlockProof:    b.GetBeaconBlockProof(),
		BeaconBlockRoot:     b.GetBeaconBlockRoot(),
		ExecutionBlockProof: b.GetExecutionBlockProof(),
		Slot:                b.Slot,
	}
}

func parseBeaconBlockProof(dir string) ([]beaconBlockProof, error) {
	res := make([]beaconBlockProof, 0)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			proof := new(beaconBlockProof)
			err = yaml.Unmarshal(content, proof)
			if err != nil {
				return err
			}
			res = append(res, *proof)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func parseHistorySummaries() ([]capella.HistoricalSummary, error) {
	content, err := os.ReadFile("./testdata/beacon_data/historical_summaries_at_slot_11476992.ssz")
	if err != nil {
		return nil, err
	}
	summaries := new(capella.HistoricalSummaries)
	reader := codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content)))
	err = summaries.Deserialize(configs.Mainnet, reader)
	if err != nil {
		return nil, err
	}
	return []capella.HistoricalSummary(*summaries), nil
}
