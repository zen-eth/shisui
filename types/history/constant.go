package history

const (
	EpochSize                  = 8192
	MergeBlockNumber    uint64 = 15_537_394 // first POS block
	ShanghaiBlockNumber uint64 = 17_034_870
	// cancunNumber represents the block number at which the Cancun hard fork activates.
	// Reference: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/cancun.md
	CancunNumber   uint64 = 19_426_587
	PreMergeEpochs        = (MergeBlockNumber + EpochSize - 1) / EpochSize
)
