package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdate(t *testing.T) {
	epochAcc, err := getEpochAccu("0xcddbda3fd6f764602c06803ff083dbfc73f2bb396df17a31e5457329b9a0f38d")
	assert.NoError(t, err)

	startNumber := 1000000
	epochRecordIndex := GetHeaderRecordIndex(uint64(startNumber))

	newEpochAcc := NewAccumulator()

	for i := 0; i <= int(epochRecordIndex); i++ {
		tmp := make([]byte, 64)
		copy(tmp, epochAcc.HeaderRecords[i])
		newEpochAcc.currentEpoch.records = append(newEpochAcc.currentEpoch.records, tmp)
	}
	startDifficulty := uint256.NewInt(0)
	err = startDifficulty.UnmarshalSSZ(epochAcc.HeaderRecords[epochRecordIndex][32:])

	require.NoError(t, err)

	newEpochAcc.currentEpoch.difficulty = startDifficulty

	for i := startNumber + 1; i <= 1000010; i++ {
		header, err := getHeader(uint64(i))
		assert.NoError(t, err)
		err = newEpochAcc.Update(*header)
		assert.NoError(t, err)
		currIndex := GetHeaderRecordIndex(uint64(i))
		assert.True(t, bytes.Equal(newEpochAcc.currentEpoch.records[currIndex], epochAcc.HeaderRecords[currIndex]))
	}
}

func getEpochAccu(name string) (EpochAccumulator, error) {
	epochAccu := EpochAccumulator{
		HeaderRecords: make([][]byte, 0),
	}
	epochData, err := os.ReadFile(fmt.Sprintf("./testdata/%s.bin", name))
	if err != nil {
		return epochAccu, err
	}
	err = epochAccu.UnmarshalSSZ(epochData)
	return epochAccu, err
}

func getHeader(number uint64) (*types.Header, error) {
	headerFile, err := os.ReadFile("./testdata/header_rlps.json")
	if err != nil {
		return nil, err
	}
	contentMap := make(map[string]string)
	err = json.Unmarshal(headerFile, &contentMap)
	if err != nil {
		return nil, err
	}
	headerStr := contentMap[strconv.FormatUint(number, 10)]
	headerBytes, err := hexutil.Decode(headerStr)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(headerBytes)
	head := &types.Header{}
	err = rlp.Decode(reader, head)
	return head, err
}

func TestFlatBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    [][]byte
		expected []byte
	}{
		{
			name:     "empty input",
			input:    [][]byte{},
			expected: []byte{},
		},
		{
			name:     "single byte array",
			input:    [][]byte{{1, 2, 3}},
			expected: []byte{1, 2, 3},
		},
		{
			name:     "multiple byte arrays",
			input:    [][]byte{{1, 2}, {3, 4}, {5, 6}},
			expected: []byte{1, 2, 3, 4, 5, 6},
		},
		{
			name:     "arrays with different lengths",
			input:    [][]byte{{1}, {2, 3, 4}, {5}},
			expected: []byte{1, 2, 3, 4, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := flatBytes(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("flatBytes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestToAccumulatorProof(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected [][]byte
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: [][]byte{},
		},
		{
			name:     "exactly 32 bytes",
			input:    bytes.Repeat([]byte{1}, 32),
			expected: [][]byte{bytes.Repeat([]byte{1}, 32)},
		},
		{
			name:     "less than 32 bytes",
			input:    []byte{1, 2, 3},
			expected: [][]byte{append([]byte{1, 2, 3}, make([]byte, 29)...)},
		},
		{
			name:  "more than 32 bytes",
			input: bytes.Repeat([]byte{1}, 40),
			expected: [][]byte{
				bytes.Repeat([]byte{1}, 32),
				append(bytes.Repeat([]byte{1}, 8), make([]byte, 24)...),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toAccumulatorProof(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("toAccumulatorProof() = %v, want %v", result, tt.expected)
			}
		})
	}
}
