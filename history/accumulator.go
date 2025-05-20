package history

import (
	_ "embed"
	"encoding/binary"
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	ssz "github.com/ferranbt/fastssz"
	"github.com/holiman/uint256"
)

const (
	epochSize                  = 8192
	mergeBlockNumber    uint64 = 15537394 // first POS block
	shanghaiBlockNumber uint64 = 17_034_870
	// cancunNumber represents the block number at which the Cancun hard fork activates.
	// Reference: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/cancun.md
	cancunNumber   uint64 = 19_426_587
	preMergeEpochs        = (mergeBlockNumber + epochSize - 1) / epochSize
)

var (
	ErrNotPreMergeHeader           = errors.New("must be pre merge header")
	ErrPreMergeHeaderMustWithProof = errors.New("pre merge header must has accumulator proof")
)

var zeroRecordBytes = make([]byte, 64)

type AccumulatorProof [][]byte

type epoch struct {
	records    [][]byte
	difficulty *uint256.Int
}

func newEpoch() *epoch {
	return &epoch{
		records:    make([][]byte, 0, epochSize),
		difficulty: uint256.NewInt(0),
	}
}

func (e *epoch) add(header types.Header) error {
	blockHash := header.Hash().Bytes()
	difficulty := uint256.MustFromBig(header.Difficulty)
	e.difficulty = uint256.NewInt(0).Add(e.difficulty, difficulty)

	difficultyBytes, err := e.difficulty.MarshalSSZ()
	if err != nil {
		return err
	}
	record := HeaderRecord{
		BlockHash:       blockHash,
		TotalDifficulty: difficultyBytes,
	}
	sszBytes, err := record.MarshalSSZ()
	if err != nil {
		return err
	}
	e.records = append(e.records, sszBytes)
	return nil
}

type Accumulator struct {
	historicalEpochs [][]byte
	currentEpoch     *epoch
}

func NewAccumulator() *Accumulator {
	return &Accumulator{
		historicalEpochs: make([][]byte, 0, int(preMergeEpochs)),
		currentEpoch:     newEpoch(),
	}
}

func (a *Accumulator) Update(header types.Header) error {
	if header.Number.Uint64() >= mergeBlockNumber {
		return ErrNotPreMergeHeader
	}

	if len(a.currentEpoch.records) == epochSize {
		epochAccu := EpochAccumulator{
			HeaderRecords: a.currentEpoch.records,
		}
		root, err := epochAccu.HashTreeRoot()
		if err != nil {
			return err
		}
		a.historicalEpochs = append(a.historicalEpochs, MixInLength(root, epochSize))
		a.currentEpoch = newEpoch()
	}
	err := a.currentEpoch.add(header)
	if err != nil {
		return err
	}
	return nil
}

func (a *Accumulator) Finish() (*MasterAccumulator, error) {
	// padding with zero bytes
	for len(a.currentEpoch.records) < epochSize {
		a.currentEpoch.records = append(a.currentEpoch.records, zeroRecordBytes)
	}
	epochAccu := EpochAccumulator{
		HeaderRecords: a.currentEpoch.records,
	}
	root, err := epochAccu.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	a.historicalEpochs = append(a.historicalEpochs, MixInLength(root, epochSize))
	return &MasterAccumulator{
		HistoricalEpochs: a.historicalEpochs,
	}, nil
}

func GetEpochIndex(blockNumber uint64) uint64 {
	return blockNumber / epochSize
}

func GetEpochIndexByHeader(header types.Header) uint64 {
	return GetEpochIndex(header.Number.Uint64())
}

func GetHeaderRecordIndex(blockNumber uint64) uint64 {
	return blockNumber % epochSize
}

func GetHeaderRecordIndexByHeader(header types.Header) uint64 {
	return GetHeaderRecordIndex(header.Number.Uint64())
}

func BuildProof(header types.Header, epochAccumulator EpochAccumulator) (AccumulatorProof, error) {
	tree, err := epochAccumulator.GetTree()
	if err != nil {
		return nil, err
	}
	index := GetHeaderRecordIndexByHeader(header)
	// maybe the calculation of index should impl in ssz
	proofIndex := epochSize*2 + index*2
	sszProof, err := tree.Prove(int(proofIndex))
	if err != nil {
		return nil, err
	}
	// the epoch hash root has mix in with epochsize, so we have to add it to proof
	hashes := sszProof.Hashes
	sizeBytes := make([]byte, 32)
	binary.LittleEndian.PutUint32(sizeBytes, epochSize)
	hashes = append(hashes, sizeBytes)
	return hashes, err
}

func BuildHeaderWithProof(header types.Header, epochAccumulator EpochAccumulator) (*BlockHeaderWithProof, error) {
	proof, err := BuildProof(header, epochAccumulator)
	if err != nil {
		return nil, err
	}
	rlpBytes, err := rlp.EncodeToBytes(header)
	if err != nil {
		return nil, err
	}
	return &BlockHeaderWithProof{
		Header: rlpBytes,
		Proof:  flatBytes(proof),
	}, nil
}

func MixInLength(root [32]byte, length uint64) []byte {
	hash := ssz.NewHasher()
	hash.AppendBytes32(root[:])
	hash.MerkleizeWithMixin(0, length, 0)
	// length of root is 32, so we can ignore the error
	newRoot, _ := hash.HashRoot()
	return newRoot[:]
}

func flatBytes(b [][]byte) []byte {
	total := 0
	for _, bytes := range b {
		total += len(bytes)
	}

	result := make([]byte, total)
	current := 0

	for _, bytes := range b {
		copy(result[current:], bytes)
		current += len(bytes)
	}
	return result
}

func toAccumulatorProof(data []byte) [][]byte {
	if len(data) == 0 {
		return [][]byte{}
	}

	numChunks := (len(data) + 31) / 32
	result := make([][]byte, numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * 32
		end := start + 32
		if end > len(data) {
			end = len(data)
		}

		chunk := make([]byte, 32)
		copy(chunk, data[start:end])
		result[i] = chunk
	}

	return result
}
