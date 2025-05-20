package history

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/util/merkle"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/tree"
	"github.com/protolambda/ztyp/view"
	"github.com/zen-eth/shisui/types/history"
	"github.com/zen-eth/shisui/validation"
)

const (
	CapellaForkEpoch uint64 = 194_048
	SlotsPerEpoch    uint64 = 32
)

func VerifyCapellaToDenebHeader(headerHash []byte, proof *history.BlockProofHistoricalSummariesCapella, historicalSummaries capella.HistoricalSummaries) bool {
	if !VerifyBellatrixToDenebExecutionBlockProof(headerHash, proof.GetExecutionBlockProof(), tree.Root(proof.BeaconBlockRoot)) {
		return false
	}
	blockRootIndex := proof.Slot % epochSize
	genIndex := epochSize + blockRootIndex
	historicalSummaryIndex := (proof.Slot - CapellaForkEpoch*SlotsPerEpoch) / epochSize
	historicalSummary := historicalSummaries[historicalSummaryIndex].BlockSummaryRoot
	return merkle.VerifyMerkleBranch(tree.Root(proof.BeaconBlockRoot), proof.GetBeaconBlockProof(), 13, genIndex, historicalSummary)
}

func VerifyPostDenebHeader(headerHash []byte, proof *history.BlockProofHistoricalSummariesDeneb, historicalSummaries capella.HistoricalSummaries) bool {
	if !VerifyPostDenebExecutionBlockProof(headerHash, proof.GetExecutionBlockProof(), tree.Root(proof.BeaconBlockRoot)) {
		return false
	}
	blockRootIndex := proof.Slot % epochSize
	genIndex := epochSize + blockRootIndex
	historicalSummaryIndex := (proof.Slot - CapellaForkEpoch*SlotsPerEpoch) / epochSize
	historicalSummary := historicalSummaries[historicalSummaryIndex].BlockSummaryRoot
	return merkle.VerifyMerkleBranch(tree.Root(proof.BeaconBlockRoot), proof.GetBeaconBlockProof(), 13, genIndex, historicalSummary)
}

func VerifyBellatrixToDenebExecutionBlockProof(headerHash []byte, elProof []tree.Root, root tree.Root) bool {
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

func VerifyPostDenebExecutionBlockProof(headerHash []byte, elProof []tree.Root, root tree.Root) bool {
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

var _ validation.Validator = &HistoryValidator{}

type HistoryValidator struct {
	validationOracle validation.Oracle
	headerValidator  validation.HeaderValidator
}

func NewHistoryValidator(oracle validation.Oracle) *HistoryValidator {
	headerValidator := validation.NewHeaderValidatorWithOracle(oracle)
	return &HistoryValidator{
		headerValidator:  headerValidator,
		validationOracle: oracle,
	}
}

// ValidationContent implements validation.Validator.
func (h *HistoryValidator) ValidateContent(contentKey []byte, content []byte) error {
	switch history.ContentType(contentKey[0]) {
	case history.BlockHeaderType:
		headerWithProof, err := history.DecodeBlockHeaderWithProof(content)
		if err != nil {
			return err
		}
		header, err := history.DecodeBlockHeader(headerWithProof.Header)
		if err != nil {
			return err
		}
		if !bytes.Equal(header.Hash().Bytes(), contentKey[1:]) {
			return ErrInvalidBlockHash
		}
		return h.headerValidator.ValidateHeaderAndProof(header, headerWithProof.Proof)
	case history.BlockHeaderNumberType:
		headerWithProof, err := history.DecodeHeaderWithProof(content)
		if err != nil {
			return err
		}
		header := headerWithProof.Header
		blockNumber := view.Uint64View(0)
		err = blockNumber.Deserialize(codec.NewDecodingReader(bytes.NewReader(contentKey[1:]), uint64(len(contentKey[1:]))))
		if err != nil {
			return err
		}
		if header.Number.Uint64() != uint64(blockNumber) {
			return ErrInvalidBlockNumber
		}
		return h.headerValidator.ValidateHeaderAndProof(header, headerWithProof.Proof)
	case history.BlockBodyType:
		header, err := h.validationOracle.GetBlockHeaderByHash(contentKey[1:])
		if err != nil {
			return err
		}
		_, err = ValidateBlockBodyBytes(content, header)
		return err
	case history.ReceiptsType:
		header, err := h.validationOracle.GetBlockHeaderByHash(contentKey[1:])
		if err != nil {
			return err
		}
		if bytes.Equal(header.ReceiptHash.Bytes(), emptyReceiptHash) {
			if len(content) > 0 {
				return fmt.Errorf("content should be empty, but received %v", content)
			}
			return nil
		}
		_, err = ValidatePortalReceiptsBytes(content, header.ReceiptHash.Bytes())
		return err
	}
	return errors.New("unknown content type in validation")
}
