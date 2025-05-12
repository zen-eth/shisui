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

func NewWithOracle(oracle *Oracle) *HistoricalSummariesProvider {
	return &HistoricalSummariesProvider{
		oracle: oracle,
		cache:  make([]capella.HistoricalSummary, 0),
	}
}

func NewWithHistorySummaries(historySummaries []capella.HistoricalSummary) *HistoricalSummariesProvider {
	return &HistoricalSummariesProvider{
		cache: historySummaries,
	}
}

func (h *HistoricalSummariesProvider) GetHistoricalSummary(slot uint64) (capella.HistoricalSummary, error) {
	epoch := slot % epochSize
	historicalSummarieIndex := (slot - capellaForkEpoch*slotsPerEpoch) / epochSize
	if historicalSummarieIndex < uint64(len(h.cache)) {
		return h.cache[historicalSummarieIndex], nil
	}
	if h.oracle == nil {
		return capella.HistoricalSummary{}, nil
	}
	historicalSummaries, err := h.oracle.GetHistoricalSummaries(epoch)
	if err != nil {
		return capella.HistoricalSummary{}, err
	}
	root := historicalSummaries[historicalSummarieIndex]
	h.cache = historicalSummaries
	return root, nil
}
