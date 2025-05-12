package history

const (
	epochSize                  = 8192
	mergeBlockNumber    uint64 = 15537394 // first POS block
	shanghaiBlockNumber uint64 = 17_034_870
	// cancunNumber represents the block number at which the Cancun hard fork activates.
	// Reference: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/cancun.md
	cancunNumber   uint64 = 19_426_587
	preMergeEpochs        = (mergeBlockNumber + epochSize - 1) / epochSize
)
