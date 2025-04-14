package portalwire

import (
	"bytes"
	"errors"
	"slices"

	bitfield "github.com/OffchainLabs/go-bitfield"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/tetratelabs/wabin/leb128"
)

var ErrUnsupportedVersion = errors.New("unsupported version")

type AcceptCode uint8

const (
	Accepted AcceptCode = iota
	GenericDeclined
	AlreadyStored
	NotWithinRadius
	RateLimited               // rate limit reached. Node can't handle anymore connections
	InboundTransferInProgress // inbound rate limit reached for accepting a specific content_id, used to protect against thundering herds
	Unspecified
)

type CommonAccept interface {
	MarshalSSZ() ([]byte, error)
	UnmarshalSSZ([]byte) error
	GetConnectionId() []byte
	SetConnectionId([]byte)
	GetContentKeys() []byte
	SetContentKeys([]byte)
	GetAcceptIndices() []int
	GetKeyLength() int
}

func (a *Accept) GetConnectionId() []byte {
	return a.ConnectionId
}
func (a *Accept) SetConnectionId(id []byte) {
	a.ConnectionId = id
}
func (a *Accept) GetContentKeys() []byte {
	return a.ContentKeys
}
func (a *Accept) SetContentKeys(keys []byte) {
	a.ContentKeys = keys
}

func (a *Accept) GetKeyLength() int {
	return int(bitfield.Bitlist(a.ContentKeys).Len())
}

func (a *Accept) GetAcceptIndices() []int {
	return bitfield.Bitlist(a.ContentKeys).BitIndices()
}

func (a *AcceptV1) GetConnectionId() []byte {
	return a.ConnectionId
}
func (a *AcceptV1) SetConnectionId(id []byte) {
	a.ConnectionId = id
}
func (a *AcceptV1) GetContentKeys() []byte {
	return a.ContentKeys
}
func (a *AcceptV1) SetContentKeys(keys []byte) {
	a.ContentKeys = keys
}

func (a *AcceptV1) GetAcceptIndices() []int {
	res := make([]int, 0)
	for i, val := range a.ContentKeys {
		if val == uint8(Accepted) {
			res = append(res, i)
		}
	}
	return res
}

func (a *AcceptV1) GetKeyLength() int {
	return len(a.GetContentKeys())
}

func (p *PortalProtocol) getHighestVersion(node *enode.Node) (uint8, error) {
	versions := &protocolVersions{}
	err := node.Load(versions)
	// key is not set, return the default version
	if enr.IsNotFound(err) {
		return p.currentVersions[0], nil
	}
	if err != nil {
		return 0, err
	}
	return findBiggestSameNumber(p.currentVersions, *versions)
}

// find the Accept.ContentKeys and the content keys to accept
func (p *PortalProtocol) filterContentKeys(request *Offer, version uint8) (CommonAccept, [][]byte, error) {
	switch version {
	case 0:
		return p.filterContentKeysV0(request)
	case 1:
		return p.filterContentKeysV1(request)
	default:
		return nil, nil, ErrUnsupportedVersion
	}
}

func (p *PortalProtocol) filterContentKeysV0(request *Offer) (CommonAccept, [][]byte, error) {
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
	accept := &Accept{
		ContentKeys: contentKeyBitlist,
	}
	return accept, acceptContentKeys, nil
}

func (p *PortalProtocol) filterContentKeysV1(request *Offer) (CommonAccept, [][]byte, error) {
	contentKeyList := make([]uint8, len(request.ContentKeys))
	acceptContentKeys := make([][]byte, 0)
	if len(p.contentQueue) >= cap(p.contentQueue) {
		for i := 0; i < len(request.ContentKeys); i++ {
			contentKeyList[i] = uint8(RateLimited)
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
						if _, exist := p.inTransferMap.Load(hexutil.Encode(contentKey)); exist {
							contentKeyList[i] = uint8(InboundTransferInProgress)
						} else {
							p.inTransferMap.Store(hexutil.Encode(contentKey), struct{}{})
							contentKeyList[i] = uint8(Accepted)
							acceptContentKeys = append(acceptContentKeys, contentKey)
						}
					}
				} else {
					contentKeyList[i] = uint8(NotWithinRadius)
				}
			} else {
				return nil, nil, ErrNilContentKey
			}
		}
	}
	accept := &AcceptV1{
		ContentKeys: contentKeyList,
	}
	return accept, acceptContentKeys, nil
}

func (p *PortalProtocol) parseOfferResp(node *enode.Node, data []byte) (CommonAccept, error) {
	version, err := p.getHighestVersion(node)
	if err != nil {
		return nil, err
	}
	switch version {
	case 0:
		accept := &Accept{}
		err = accept.UnmarshalSSZ(data)
		if err != nil {
			return nil, err
		}
		return accept, nil
	case 1:
		accept := &AcceptV1{}
		err = accept.UnmarshalSSZ(data)
		if err != nil {
			return nil, err
		}
		return accept, nil
	default:
		return nil, ErrUnsupportedVersion
	}
}

// findTheBiggestSameNumber finds the largest value that exists in both slices.
// Returns the largest common value, or an error if there are no common values.
func findBiggestSameNumber(a []uint8, b []uint8) (uint8, error) {
	if len(a) == 0 || len(b) == 0 {
		return 0, errors.New("empty slice provided")
	}

	// Create a map to track values in the first slice
	valuesInA := make(map[uint8]bool)
	for _, val := range a {
		valuesInA[val] = true
	}

	// Find common values and track the maximum
	var maxCommon uint8
	foundCommon := false

	for _, val := range b {
		if valuesInA[val] {
			foundCommon = true
			if val > maxCommon {
				maxCommon = val
			}
		}
	}

	if !foundCommon {
		return 0, errors.New("no common values found")
	}

	return maxCommon, nil
}

func (p *PortalProtocol) handleV0Offer(data []byte) []byte {
	// if currentVersions includes version 1, then we need to handle the offer
	if slices.Contains(p.currentVersions, 1) {
		bitlist := bitfield.Bitlist(data)
		v1 := make([]byte, 0)
		for i := 0; i < int(bitlist.Len()); i++ {
			exist := bitlist.BitAt(uint64(i))
			if exist {
				v1 = append(v1, byte(Accepted))
			} else {
				v1 = append(v1, byte(GenericDeclined))
			}
		}
		return v1
	} else {
		return data
	}
}

func (p *PortalProtocol) decodeUtpContent(target *enode.Node, data []byte) ([]byte, error) {
	version, err := p.getHighestVersion(target)
	if err != nil {
		return nil, err
	}
	if version == 1 {
		contentLen, bytesRead, err := leb128.DecodeUint32(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		data = data[bytesRead:]
		if len(data) != int(contentLen) {
			return nil, errors.New("content length mismatch")
		}
	}
	return data, nil
}

func (p *PortalProtocol) encodeUtpContent(target *enode.Node, data []byte) ([]byte, error) {
	version, err := p.getHighestVersion(target)
	if err != nil {
		return nil, err
	}
	if version == 1 {
		contentLen := uint32(len(data))
		contentLenBytes := leb128.EncodeUint32(contentLen)
		contentLenBytes = append(contentLenBytes, data...)
		return contentLenBytes, nil
	}
	return data, nil
}
