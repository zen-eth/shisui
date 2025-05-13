package validation

import (
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
	ssz "github.com/ferranbt/fastssz"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/util/merkle"
	"github.com/protolambda/ztyp/tree"
	"github.com/zen-eth/shisui/types/history"
)

var (
	ErrMerkleValidation    = errors.New("merkle validation error")
	ErrExecutionBlockProof = errors.New("execution block proof error")
)

type HeaderValidator struct {
	preMergeAcc                 PreMergeAccumulator
	historicalRootsAcc          HistoricalRootsAccumulator
	historicalSummariesProvider *HistoricalSummariesProvider
}

func NewHeaderValidatorWithOracle(oracle *Oracle) HeaderValidator {
	return HeaderValidator{
		preMergeAcc:                 DefaultPreMergeAccumulator(),
		historicalRootsAcc:          DefaultHistoricalRootsAccumulator(),
		historicalSummariesProvider: NewWithOracle(oracle),
	}
}

func NewHeaderValidatorWithHistorySummaries(historySummaries []capella.HistoricalSummary) HeaderValidator {
	return HeaderValidator{
		preMergeAcc:                 DefaultPreMergeAccumulator(),
		historicalRootsAcc:          DefaultHistoricalRootsAccumulator(),
		historicalSummariesProvider: NewWithHistorySummaries(historySummaries),
	}
}

func (h HeaderValidator) ValidateHeaderWithProof(headerWithProof *history.BlockHeaderWithProof) error {
	header, err := history.DecodeBlockHeader(headerWithProof.Header)
	if err != nil {
		return err
	}
	return h.validateHeaderWithProof(header, headerWithProof.Proof)
}

func (h HeaderValidator) validateHeaderWithProof(header *types.Header, proof []byte) error {
	blockNumber := header.Number.Uint64()
	if blockNumber <= history.MergeBlockNumber {
		return h.validatePreMergeHeader(header, proof)
	} else if blockNumber < history.ShanghaiBlockNumber {
		blockProofHistoricalRoots := &history.BlockProofHistoricalRoots{}
		err := blockProofHistoricalRoots.UnmarshalSSZ(proof)
		if err != nil {
			return err
		}
		return h.validateMergeToCapellaHeader(header.Hash().Bytes(), blockProofHistoricalRoots)
	} else if blockNumber < history.CancunNumber {
		blockProof := new(history.BlockProofHistoricalSummariesCapella)
		err := blockProof.UnmarshalSSZ(proof)
		if err != nil {
			return err
		}
		return h.validateCapellaToDenebHeader(header.Hash().Bytes(), blockProof)
	} else {
		blockProof := new(history.BlockProofHistoricalSummariesDeneb)
		err := blockProof.UnmarshalSSZ(proof)
		if err != nil {
			return err
		}
		return h.validatePostDenebHeader(header.Hash().Bytes(), blockProof)
	}
}

func (h HeaderValidator) validatePreMergeHeader(header *types.Header, proof []byte) error {
	epochIndex := history.GetEpochIndexByHeader(*header)
	root := h.preMergeAcc.HistoricalEpochs[epochIndex]

	recordIndex := history.GetHeaderRecordIndexByHeader(*header)

	index := epochSize*2*2 + recordIndex*2

	branches, err := TurnToPreMergeProof(proof)
	if err != nil {
		return err
	}

	sszProof := &ssz.Proof{
		Index:  int(index),
		Leaf:   header.Hash().Bytes(),
		Hashes: branches,
	}
	valid, err := ssz.VerifyProof(root, sszProof)
	if err != nil {
		return err
	}
	if !valid {
		return ErrMerkleValidation
	}
	return nil
}

func (h HeaderValidator) validateMergeToCapellaHeader(headerHash []byte, proof *history.BlockProofHistoricalRoots) error {
	valid := h.verifyBellatrixToDenebExecutionBlockProof(headerHash, proof.GetExecutionBlockProof(), tree.Root(proof.BeaconBlockRoot))
	if !valid {
		return ErrExecutionBlockProof
	}
	blockRootIndex := proof.Slot % epochSize
	genIndex := 2*epochSize + blockRootIndex
	historicalRootIndex := proof.Slot / epochSize
	historicalRoot := h.historicalRootsAcc.HistoricalRoots[historicalRootIndex]

	if !merkle.VerifyMerkleBranch(tree.Root(proof.BeaconBlockRoot), proof.GetBeaconBlockProof()[:], 14, genIndex, historicalRoot) {
		return errors.New("merkle proof validation failed for HistoricalRootsProof")
	}
	return nil
}

func (h HeaderValidator) validateCapellaToDenebHeader(headerHash []byte, proof *history.BlockProofHistoricalSummariesCapella) error {
	valid := h.verifyBellatrixToDenebExecutionBlockProof(headerHash, proof.GetExecutionBlockProof(), tree.Root(proof.BeaconBlockRoot))
	if !valid {
		return ErrExecutionBlockProof
	}
	historicSummary, err := h.historicalSummariesProvider.GetHistoricalSummary(proof.Slot)
	if err != nil {
		return err
	}

	blockRootIndex := proof.Slot % epochSize
	genIndex := epochSize + blockRootIndex

	if !merkle.VerifyMerkleBranch(tree.Root(proof.BeaconBlockRoot), proof.GetBeaconBlockProof(), 13, genIndex, historicSummary.BlockSummaryRoot) {
		return ErrMerkleValidation
	}
	return nil
}

func (h HeaderValidator) validatePostDenebHeader(headerHash []byte, proof *history.BlockProofHistoricalSummariesDeneb) error {
	valid := h.verifyPostDenebExecutionBlockProof(headerHash, proof.GetExecutionBlockProof(), tree.Root(proof.BeaconBlockRoot))
	if !valid {
		return ErrExecutionBlockProof
	}
	historicSummary, err := h.historicalSummariesProvider.GetHistoricalSummary(proof.Slot)
	if err != nil {
		return err
	}

	blockRootIndex := proof.Slot % epochSize
	genIndex := epochSize + blockRootIndex

	if !merkle.VerifyMerkleBranch(tree.Root(proof.BeaconBlockRoot), proof.GetBeaconBlockProof(), 13, genIndex, historicSummary.BlockSummaryRoot) {
		return ErrMerkleValidation
	}
	return nil
}

func (h HeaderValidator) verifyBellatrixToDenebExecutionBlockProof(headerHash []byte, elProof []tree.Root, root tree.Root) bool {
	// BeaconBlock level:
	// - 8 as there are 5 fields
	// - 4 as index (pos) of field is 4
	// let gen_index_top_level = (1 * 1 * 8 + 4)
	// BeaconBlockBody level:
	// - 16 as there are 10 fields
	// - 9 as index (pos) of field is 9
	// let gen_index_mid_level = (gen_index_top_level * 1 * 16 + 9)
	// ExecutionPayload level:
	// - 16 as there are 14 fields
	// - 12 as pos of field is 12
	// let gen_index = (gen_index_mid_level * 1 * 16 + 12) = 3228
	var gIndex uint64 = 3228
	return merkle.VerifyMerkleBranch(tree.Root(headerHash), elProof, uint64(len(elProof)), gIndex, root)
}

func (h HeaderValidator) verifyPostDenebExecutionBlockProof(headerHash []byte, elProof []tree.Root, root tree.Root) bool {
	// BeaconBlock level:
	// - 8 as there are 5 fields
	// - 4 as index (pos) of field is 4
	// let gen_index_top_level = (1 * 8 + 4) = 12
	// BeaconBlockBody level:
	// - 16 as there are 12 fields
	// - 9 as index (pos) of field is 9
	// let gen_index_mid_level = (gen_index_top_level * 16 + 9) = 201
	// ExecutionPayload level:
	// - 32 as there are 17 fields
	// - 12 as pos of field is 12
	// let gen_index = (gen_index_mid_level * 32 + 12) = 6444
	var gIndex uint64 = 6444
	return merkle.VerifyMerkleBranch(tree.Root(headerHash), elProof, uint64(len(elProof)), gIndex, root)
}

func TurnToPreMergeProof(proof []byte) ([][]byte, error) {
	if len(proof)%32 != 0 {
		return nil, errors.New("proof length should be 32*n bytes")
	}
	numChunks := len(proof) / 32

	result := make([][]byte, numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * 32
		end := start + 32

		chunk := make([]byte, 32)
		copy(chunk, proof[start:end])
		result[i] = chunk
	}
	return result, nil
}

func MixInLength(root [32]byte, length uint64) []byte {
	hash := ssz.NewHasher()
	hash.AppendBytes32(root[:])
	hash.MerkleizeWithMixin(0, length, 0)
	// length of root is 32, so we can ignore the error
	newRoot, _ := hash.HashRoot()
	return newRoot[:]
}
