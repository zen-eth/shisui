package state

import (
	"context"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/zen-eth/shisui/portalwire"
	"github.com/zen-eth/shisui/validation"
)

type Network struct {
	portalProtocol *portalwire.PortalProtocol
	closeCtx       context.Context
	closeFunc      context.CancelFunc
	log            log.Logger
	spec           *common.Spec
	validator      validation.Validator
}

func NewStateNetwork(portalProtocol *portalwire.PortalProtocol, validator validation.Validator) *Network {
	ctx, cancel := context.WithCancel(context.Background())
	return &Network{
		portalProtocol: portalProtocol,
		closeCtx:       ctx,
		closeFunc:      cancel,
		log:            log.New("sub-protocol", "state"),
		spec:           configs.Mainnet,
		validator:      validator,
	}
}

func (h *Network) Start() error {
	err := h.portalProtocol.Start()
	if err != nil {
		return err
	}
	go h.processContentLoop(h.closeCtx)
	h.log.Debug("state network start successfully")
	return nil
}

func (h *Network) Stop() {
	h.closeFunc()
	h.portalProtocol.Stop()
}

func (h *Network) processContentLoop(ctx context.Context) {
	contentChan := h.portalProtocol.GetContent()
	for {
		select {
		case <-ctx.Done():
			return
		case contentElement := <-contentChan:
			err := h.validateContents(contentElement.ContentKeys, contentElement.Contents)
			if err != nil {
				continue
			}

			go func(ctx context.Context) {
				select {
				case <-ctx.Done():
					return
				default:
					var gossippedNum int
					gossippedNum, err := h.portalProtocol.Gossip(&contentElement.Node, contentElement.ContentKeys, contentElement.Contents)
					h.log.Trace("gossippedNum", "gossippedNum", gossippedNum)
					if err != nil {
						h.log.Error("gossip failed", "err", err)
						return
					}
				}
			}(ctx)
		}
	}
}

func (h *Network) validateContents(contentKeys [][]byte, contents [][]byte) error {
	for i, content := range contents {
		contentKey := contentKeys[i]
		err := h.validator.ValidateContent(contentKey, content)
		if err != nil {
			h.log.Error("content validate failed", "contentKey", hexutil.Encode(contentKey), "err", err)
			return err
		}
		contentId := h.portalProtocol.ToContentId(contentKey)
		err = h.portalProtocol.Put(contentKey, contentId, content)
		if err != nil {
			return err
		}
	}
	return nil
}
