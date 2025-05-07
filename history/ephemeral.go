package history

import (
	"bytes"
	"fmt"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/zen-eth/shisui/beacon"
)

func (h *Network) isEphemeralOfferType(contentKey []byte) bool {
	return ContentType(contentKey[0]) == OfferEphemeralType
}

func (h *Network) handleEphemeralContents(contentKeys [][]byte, contents [][]byte) error {
	var parentHash gcommon.Hash
	gotHead := false
	headHash, err := h.externalOracle.GetHeadHash()
	if err != nil {
		return err
	}
	for i, content := range contents {
		contentKey := contentKeys[i]
		if !h.isEphemeralOfferType(contentKey) {
			return fmt.Errorf("content key diferent of type Ephemeral: content key %x", contentKey)
		}

		header, err := DecodeBlockHeader(content)
		if err != nil {
			return err
		}

		if !gotHead && headHash.Cmp(header.Hash()) != 0 {
			h.log.Info("ephemeral header is not HEAD", "hash", header.Hash())
			continue
		} else if headHash.Cmp(header.Hash()) == 0 {
			gotHead = true
		}

		headerhash := header.Hash()
		h.portalProtocol.EphemeralHeaderCacheRWLock.RLock()
		has := h.portalProtocol.EphemeralHeaderCache.Has(headerhash.Bytes())
		h.portalProtocol.EphemeralHeaderCacheRWLock.RUnlock()
		if has {
			return nil
		} else {
			if headHash.Cmp(header.Hash()) != 0 && parentHash.Cmp(headerhash) != 0 {
				return fmt.Errorf("hash diferent from last block paretHash: hash %x, paretHash %x", headerhash, parentHash)
			}

			if !bytes.Equal(headerhash.Bytes(), contentKey[1:]) {
				return fmt.Errorf("header hash diferent from block_hash: header hash %x, content key %x", headerhash, contentKey[1:])
			}

			he, err := header.MarshalJSON()
			if err != nil {
				return err
			}
			h.portalProtocol.EphemeralHeaderCacheRWLock.Lock()
			h.portalProtocol.EphemeralHeaderCache.Set(headerhash.Bytes(), he)
			h.portalProtocol.EphemeralHeaderCacheRWLock.Unlock()
		}

		parentHash = header.ParentHash
	}
	return nil
}

type ExternalOracle struct {
	beacon         *beacon.Network
	externalOracle string
}

func NewExternalOracle(externalOracle string, beacon *beacon.Network) *ExternalOracle {
	eo := &ExternalOracle{
		externalOracle: externalOracle,
		beacon:         beacon,
	}
	return eo
}

func (eo *ExternalOracle) GetHeadHash() (*gcommon.Hash, error) {
	if len(eo.externalOracle) <= 0 {
		return eo.beacon.GetHeadHash()
	} else {
		return eo.beacon.GetHeadHashFromExternal(eo.externalOracle)
	}
}
