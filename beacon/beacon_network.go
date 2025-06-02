package beacon

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	ssz "github.com/ferranbt/fastssz"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/tree"
	"github.com/zen-eth/shisui/portalwire"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/types/beacon"
	"github.com/zen-eth/shisui/validation"
)

const (
	LightClientBootstrap        storage.ContentType = 0x10
	LightClientUpdate           storage.ContentType = 0x11
	LightClientFinalityUpdate   storage.ContentType = 0x12
	LightClientOptimisticUpdate storage.ContentType = 0x13
	HistoricalSummaries         storage.ContentType = 0x14
)

type Network struct {
	portalProtocol *portalwire.PortalProtocol
	spec           *common.Spec
	log            log.Logger
	closeCtx       context.Context
	closeFunc      context.CancelFunc
	lightClient    *ConsensusLightClient
	validator      validation.Validator
}

func NewBeaconNetwork(portalProtocol *portalwire.PortalProtocol, client *ConsensusLightClient, validator validation.Validator) *Network {
	ctx, cancel := context.WithCancel(context.Background())

	return &Network{
		portalProtocol: portalProtocol,
		spec:           configs.Mainnet,
		closeCtx:       ctx,
		closeFunc:      cancel,
		log:            log.New("sub-protocol", "beacon"),
		lightClient:    client,
		validator:      validator,
	}
}

func (bn *Network) Start() error {
	err := bn.portalProtocol.Start()
	if err != nil {
		return err
	}
	go func() {
		err := bn.lightClient.Start()
		if err != nil {
			bn.log.Error("failed to start light client", "err", err)
		}
	}()
	go bn.processContentLoop(bn.closeCtx)
	bn.log.Debug("beacon network start successfully")
	return nil
}

func (bn *Network) Stop() {
	bn.closeFunc()
	bn.portalProtocol.Stop()
}

func (bn *Network) GetUpdates(firstPeriod, count uint64) ([]common.SpecObj, error) {
	lightClientUpdateKey := &beacon.LightClientUpdateKey{
		StartPeriod: firstPeriod,
		Count:       count,
	}

	data, err := bn.getContent(LightClientUpdate, lightClientUpdateKey)
	if err != nil {
		return nil, err
	}
	var lightClientUpdateRange beacon.LightClientUpdateRange = make([]beacon.ForkedLightClientUpdate, 0)
	err = lightClientUpdateRange.Deserialize(bn.spec, codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	if err != nil {
		return nil, err
	}
	res := make([]common.SpecObj, len(lightClientUpdateRange))

	for i, item := range lightClientUpdateRange {
		res[i] = item.LightClientUpdate
	}
	return res, nil
}

func (bn *Network) GetCheckpointData(checkpointHash tree.Root) (common.SpecObj, error) {
	bootstrapKey := &beacon.LightClientBootstrapKey{
		BlockHash: checkpointHash[:],
	}

	data, err := bn.getContent(LightClientBootstrap, bootstrapKey)
	if err != nil {
		return nil, err
	}

	var forkedLightClientBootstrap *beacon.ForkedLightClientBootstrap
	err = forkedLightClientBootstrap.Deserialize(bn.spec, codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	if err != nil {
		return nil, err
	}
	return forkedLightClientBootstrap.Bootstrap, nil
}

func (bn *Network) GetFinalityUpdate(finalizedSlot uint64) (common.SpecObj, error) {
	finalityUpdateKey := &beacon.LightClientFinalityUpdateKey{
		FinalizedSlot: finalizedSlot,
	}
	data, err := bn.getContent(LightClientFinalityUpdate, finalityUpdateKey)
	if err != nil {
		return nil, err
	}

	var forkedLightClientFinalityUpdate *beacon.ForkedLightClientFinalityUpdate
	err = forkedLightClientFinalityUpdate.Deserialize(bn.spec, codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	if err != nil {
		return nil, err
	}

	return forkedLightClientFinalityUpdate.LightClientFinalityUpdate, nil
}

func (bn *Network) GetOptimisticUpdate(optimisticSlot uint64) (common.SpecObj, error) {
	optimisticUpdateKey := &beacon.LightClientOptimisticUpdateKey{
		OptimisticSlot: optimisticSlot,
	}

	data, err := bn.getContent(LightClientOptimisticUpdate, optimisticUpdateKey)
	if err != nil {
		return nil, err
	}

	var forkedLightClientOptimisticUpdate *beacon.ForkedLightClientOptimisticUpdate
	err = forkedLightClientOptimisticUpdate.Deserialize(bn.spec, codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
	if err != nil {
		return nil, err
	}

	return forkedLightClientOptimisticUpdate.LightClientOptimisticUpdate, nil
}

func (bn *Network) getContent(contentType storage.ContentType, beaconContentKey ssz.Marshaler) ([]byte, error) {
	contentKeyBytes, err := beaconContentKey.MarshalSSZ()
	if err != nil {
		return nil, err
	}

	contentKey := storage.NewContentKey(contentType, contentKeyBytes).Encode()
	contentId := bn.portalProtocol.ToContentId(contentKey)

	res, err := bn.portalProtocol.Get(contentKey, contentId)
	// other error
	if err != nil && !errors.Is(err, storage.ErrContentNotFound) {
		return nil, err
	}

	if res != nil {
		return res, nil
	}

	content, _, err := bn.portalProtocol.ContentLookup(contentKey, contentId)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func (bn *Network) validateContents(contentKeys [][]byte, contents [][]byte) error {
	for i, content := range contents {
		contentKey := contentKeys[i]
		err := bn.validator.ValidateContent(contentKey, content)
		if err != nil {
			if metrics.Enabled() {
				if errors.Is(err, validation.ErrOracle) {
					bn.portalProtocol.GetMetrics().ValidationOracleFailed.Inc(1)
				} else {
					bn.portalProtocol.GetMetrics().ValidationNormalFailed.Inc(1)
				}
			}
			bn.log.Error("content validate failed", "contentKey", hexutil.Encode(contentKey), "err", err)
			return fmt.Errorf("content validate failed with content key %x", contentKey)
		}
		contentId := bn.portalProtocol.ToContentId(contentKey)
		err = bn.portalProtocol.Put(contentKey, contentId, content)
		if err != nil {
			bn.log.Error("put content failed", "contentKey", hexutil.Encode(contentKey), "err", err)
			return err
		}
	}
	return nil
}

func (bn *Network) processContentLoop(ctx context.Context) {
	contentChan := bn.portalProtocol.GetContent()
	for {
		select {
		case <-ctx.Done():
			return
		case contentElement := <-contentChan:
			if metrics.Enabled() {
				bn.portalProtocol.GetMetrics().ContentQueueGauge.Dec(1)
			}
			err := bn.validateContents(contentElement.ContentKeys, contentElement.Contents)
			if err != nil {
				bn.log.Error("validate content failed", "err", err)
				continue
			}
			go func(ctx context.Context) {
				select {
				case <-ctx.Done():
					return
				default:
					var gossippedNum int
					gossippedNum, err = bn.portalProtocol.Gossip(&contentElement.Node, contentElement.ContentKeys, contentElement.Contents)
					bn.log.Trace("gossippedNum", "gossippedNum", gossippedNum)
					if err != nil {
						bn.log.Error("gossip failed", "err", err)
						return
					}
				}
			}(ctx)
		}
	}
}
