package validation

import (
	"bytes"
	_ "embed"

	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/codec"
)

//go:embed assets/merge_macc.bin
var preMergeAccumulator []byte

func DefaultPreMergeAccumulator() PreMergeAccumulator {
	var masterAcc = PreMergeAccumulator{
		HistoricalEpochs: make([][]byte, 0),
	}
	_ = masterAcc.UnmarshalSSZ(preMergeAccumulator)
	return masterAcc
}

//go:embed assets/historical_roots.ssz
var historicalRootsBytes []byte

// merge to pre capella accumulator
type HistoricalRootsAccumulator struct {
	HistoricalRoots HistoricalRoots
}

func DefaultHistoricalRootsAccumulator() HistoricalRootsAccumulator {
	return NewHistoricalRootsAccumulator(configs.Mainnet)
}

func NewHistoricalRootsAccumulator(spec *common.Spec) HistoricalRootsAccumulator {
	historicalRoots := new(HistoricalRoots)
	reader := codec.NewDecodingReader(bytes.NewReader(historicalRootsBytes), uint64(len(historicalRootsBytes)))
	err := historicalRoots.Deserialize(spec, reader)
	if err != nil {
		panic(err)
	}
	return HistoricalRootsAccumulator{HistoricalRoots: *historicalRoots}
}
