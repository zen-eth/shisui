package portalwire

import (
	"errors"

	"github.com/prysmaticlabs/go-bitfield"
)

var ErrUnsupportedVersion = errors.New("unsupported version")

// TODO: get current version, should pass a node
func (p *PortalProtocol) getVersion() uint8 {
	return 0
}

// find the Accept.ContentKeys and the content keys to accept
func (p *PortalProtocol) findContentKeys(request *Offer) ([]byte, [][]byte, error) {
	switch p.getVersion() {
	case 0:
		return p.findContentKeysV0(request)
	case 1:
		return p.findContentKeysV1(request)
	default:
		return nil, nil, ErrUnsupportedVersion
	}
}

func (p *PortalProtocol) findContentKeysV0(request *Offer) ([]byte, [][]byte, error) {
	contentKeyBitlist := bitfield.NewBitlist(uint64(len(request.ContentKeys)))
	acceptContentKeys := make([][]byte, 0)
	if len(p.contentQueue) < cap(p.contentQueue) {
		for i, contentKey := range request.ContentKeys {
			contentId := p.toContentId(contentKey)
			if contentId != nil {
				if inRange(p.Self().ID(), p.Radius(), contentId) {
					if _, err := p.storage.Get(contentKey, contentId); err != nil {
						contentKeyBitlist.SetBitAt(uint64(i), true)
						acceptContentKeys = append(acceptContentKeys, contentKey)
					}
				}
			} else {
				return nil, nil, ErrNilContentKey
			}
		}
	}
	return contentKeyBitlist, acceptContentKeys, nil
}

func (p *PortalProtocol) findContentKeysV1(request *Offer) ([]byte, [][]byte, error) {
	contentKeyList := make([]uint8, len(request.ContentKeys))
	acceptContentKeys := make([][]byte, 0)
	if len(p.contentQueue) >= cap(p.contentQueue) {
		for i := 0; i < len(request.ContentKeys); i++ {
			contentKeyList[i] = uint8(InboundRateLimit)
		}
	} else {
		for i, contentKey := range request.ContentKeys {
			contentId := p.toContentId(contentKey)
			if contentId != nil {
				if inRange(p.Self().ID(), p.Radius(), contentId) {
					_, err := p.storage.Get(contentKey, contentId)
					if err == nil {
						contentKeyList[i] = uint8(AlreadyStored)
					} else {
						contentKeyList[i] = uint8(Accepted)
						acceptContentKeys = append(acceptContentKeys, contentKey)
					}
				} else {
					contentKeyList[i] = uint8(NotWithinRadius)
				}
			} else {
				return nil, nil, ErrNilContentKey
			}
		}
	}
	return contentKeyList, acceptContentKeys, nil
}
