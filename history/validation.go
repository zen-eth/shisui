package history

import (
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/util/merkle"
	"github.com/protolambda/ztyp/tree"
)

const (
	CapellaForkEpoch uint64 = 194_048
	SlotsPerEpoch    uint64 = 32
)

func VerifyPostCapellaHeader(headerHash []byte, proof *BlockProofHistoricalSummariesCapella, historicalSummaries capella.HistoricalSummaries) bool {
	if !VerifyBeaconBlock(headerHash, proof.GetExecutionBlockProof(), tree.Root(proof.BeaconBlockRoot)) {
		return false
	}

	blockRootIndex := proof.Slot % epochSize
	genIndex := epochSize + blockRootIndex
	historicalSummarieIndex := (proof.Slot - CapellaForkEpoch*SlotsPerEpoch) / epochSize
	historicalSummary := historicalSummaries[historicalSummarieIndex].BlockSummaryRoot
	return merkle.VerifyMerkleBranch(tree.Root(proof.BeaconBlockRoot), proof.GetBeaconBlockProof(), 13, genIndex, historicalSummary)
}

func VerifyBeaconBlock(headerHash []byte, elProof []tree.Root, root tree.Root) bool {
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
	return merkle.VerifyMerkleBranch(tree.Root(headerHash), elProof, 11, gIndex, root)
}
