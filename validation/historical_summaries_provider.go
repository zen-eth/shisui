package validation

import "github.com/protolambda/zrnt/eth2/beacon/capella"

const (
	epochSize               = 8192
	capellaForkEpoch uint64 = 194_048
	slotsPerEpoch    uint64 = 32
)

// post capella history summaries provider
type HistoricalSummariesProvider struct {
	cache  []capella.HistoricalSummary
	oracle *Oracle
}

func NewWithOracle(oracle *Oracle) HistoricalSummariesProvider {
	return HistoricalSummariesProvider{
		oracle: oracle,
	}
}

func NewWithHistorySummaries(historySummaries []capella.HistoricalSummary) HistoricalSummariesProvider {
	return HistoricalSummariesProvider{
		cache: historySummaries,
	}
}

func (h HistoricalSummariesProvider) GetHistoricalSummary(slot uint64) (capella.HistoricalSummary, error) {
	epoch := slot % epochSize
	historicalSummarieIndex := (slot - capellaForkEpoch*slotsPerEpoch) / epochSize
	if h.oracle == nil {
		return h.cache[historicalSummarieIndex], nil
	}
	historicalSummaries, err := h.oracle.GetHistoricalSummaries(epoch)
	if err != nil {
		return capella.HistoricalSummary{}, err
	}
	root := historicalSummaries[historicalSummarieIndex]
	return root, nil
}
