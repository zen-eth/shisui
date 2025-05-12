package validation

import (
	"bytes"
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/codec"
	"github.com/zen-eth/shisui/beacon"
	"github.com/zen-eth/shisui/portalwire"
)

type Oracle struct {
	client *rpc.Client
}

func NewOracle(client *rpc.Client) Oracle {
	return Oracle{
		client: client,
	}
}

func (o Oracle) GetHistoricalSummaries(epoch uint64) (capella.HistoricalSummaries, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
	defer cancel()
	key := beacon.HistoricalSummariesWithProofKey{
		Epoch: epoch,
	}
	var buf bytes.Buffer
	err := key.Serialize(codec.NewEncodingWriter(&buf))
	if err != nil {
		return nil, err
	}
	contentKey := make([]byte, 0)
	contentKey = append(contentKey, byte(beacon.HistoricalSummaries))
	contentKey = append(contentKey, buf.Bytes()...)

	arg := hexutil.Encode(contentKey)
	res := &portalwire.ContentInfo{}
	err = o.client.CallContext(ctx, res, "portal_beaconGetContent", arg)
	if err != nil {
		return nil, err
	}
	data, err := hexutil.Decode(res.Content)
	if err != nil {
		return nil, err
	}
	proof := new(beacon.ForkedHistoricalSummariesWithProof)
	err = proof.Deserialize(configs.Mainnet, codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	if err != nil {
		return nil, err
	}
	return proof.HistoricalSummariesWithProof.HistoricalSummaries, nil
}
