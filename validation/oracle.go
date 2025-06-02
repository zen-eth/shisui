package validation

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/codec"
	"github.com/zen-eth/shisui/portalwire"
	"github.com/zen-eth/shisui/types/beacon"
	"github.com/zen-eth/shisui/types/history"
)

var defaultTimeout = time.Second * 4

type Oracle interface {
	GetHistoricalSummaries(epoch uint64) (capella.HistoricalSummaries, error)
	GetBlockHeaderByHash(hash []byte) (*types.Header, error)
	GetFinalizedStateRoot() ([]byte, error)
}

var ErrOracle = errors.New("oracle error")

var _ Oracle = &ValidationOracle{}

type ValidationOracle struct {
	client *rpc.Client
}

func NewOracle(client *rpc.Client) *ValidationOracle {
	return &ValidationOracle{
		client: client,
	}
}

func (o *ValidationOracle) GetHistoricalSummaries(epoch uint64) (capella.HistoricalSummaries, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	key := beacon.HistoricalSummariesWithProofKey{
		Epoch: epoch,
	}
	var buf bytes.Buffer
	err := key.Serialize(codec.NewEncodingWriter(&buf))
	if err != nil {
		return nil, err
	}
	contentKey := make([]byte, 0, 1+len(buf.Bytes()))
	contentKey = append(contentKey, byte(beacon.HistoricalSummaries))
	contentKey = append(contentKey, buf.Bytes()...)

	arg := hexutil.Encode(contentKey)
	res := &portalwire.ContentInfo{}
	err = o.client.CallContext(ctx, res, "portal_beaconGetContent", arg)
	if err != nil {
		return nil, errors.Join(err, ErrOracle)
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

// GetBlockHeaderByHash implements Oracle.
func (o *ValidationOracle) GetBlockHeaderByHash(hash []byte) (*types.Header, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	contentKey := make([]byte, 0, len(hash)+1)
	contentKey = append(contentKey, 0x00)
	contentKey = append(contentKey, hash...)
	arg := hexutil.Encode(contentKey)
	res := &portalwire.ContentInfo{}
	err := o.client.CallContext(ctx, res, "portal_historyGetContent", arg)
	if err != nil {
		return nil, errors.Join(err, ErrOracle)
	}
	data, err := hexutil.Decode(res.Content)
	if err != nil {
		return nil, err
	}
	headerWithProof, err := history.DecodeBlockHeaderWithProof(data)
	if err != nil {
		return nil, err
	}
	return history.DecodeBlockHeader(headerWithProof.Header)
}

func (o *ValidationOracle) GetFinalizedStateRoot() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	res := ""
	err := o.client.CallContext(ctx, &res, "portal_beaconFinalizedStateRoot")
	if err != nil {
		return nil, errors.Join(err, ErrOracle)
	}
	root, err := hexutil.Decode(res)
	if err != nil {
		return nil, err
	}
	return root, nil
}
