package validation

type PreMergeAccumulator struct {
	HistoricalEpochs [][]byte `ssz-max:"1897,32" ssz-size:"?,32"`
}
