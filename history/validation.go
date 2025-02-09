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

func VerifyPostCapellaHeader(headerHash []byte, proof *BlockProofHistoricalSummaries, historicalSummaries capella.HistoricalSummaries) bool {
	var gIndex uint64 = 3228
	if !merkle.VerifyMerkleBranch(tree.Root(headerHash), proof.GetExecutionBlockProof(), 11, gIndex, tree.Root(proof.BeaconBlockRoot)) {
		return false
	}

	blockRootIndex := proof.Slot % epochSize
	genIndex := epochSize + blockRootIndex
	historicalSummarieIndex := (proof.Slot - CapellaForkEpoch*SlotsPerEpoch) / epochSize
	historicalSummary := historicalSummaries[historicalSummarieIndex].BlockSummaryRoot
	return merkle.VerifyMerkleBranch(tree.Root(proof.BeaconBlockRoot), proof.GetBeaconBlockProof(), 13, genIndex, historicalSummary)
}
