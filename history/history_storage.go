package history

import (
	"sync"

	cpebble "github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/holiman/uint256"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/storage/pebble"
)

type HistoryStorage struct {
	historyStorage   storage.ContentStorage
	ephemeralStorage storage.ContentStorage
}

func NewHistoyStorage(dbHistory, dbEphemeral *cpebble.DB, dataCapacity uint64, nodeId enode.ID, networkName string) (storage.ContentStorage, error) {
	cs, err := pebble.NewStorage(storage.PortalStorageConfig{
		StorageCapacityMB: dataCapacity,
		NodeId:            nodeId,
		NetworkName:       networkName,
	}, dbHistory)
	if err != nil {
		return nil, err
	}

	es := &EphemeralStorage{
		maxCapacityQuantity: uint64(ephemeralHeadersMaxQuantity),
		db:                  dbEphemeral,
		log:                 log.New("ephemeral_storage"),
		bytePool: sync.Pool{
			New: func() interface{} {
				out := make([]byte, 8)
				return &out
			},
		},
	}

	hh := &HistoryStorage{
		historyStorage:   cs,
		ephemeralStorage: es,
	}

	return hh, nil
}

func (hh *HistoryStorage) Get(contentKey []byte, contentId []byte) ([]byte, error) {
	if isEphemeralOfferType(contentKey) {
		return hh.ephemeralStorage.Get(contentKey, contentId)
	} else {
		return hh.historyStorage.Get(contentKey, contentId)
	}
}

func (hh *HistoryStorage) Put(contentKey []byte, contentId []byte, content []byte) error {
	if isEphemeralOfferType(contentKey) {
		return hh.ephemeralStorage.Put(contentKey, contentId, content)
	} else {
		return hh.historyStorage.Put(contentKey, contentId, content)
	}
}

func (hh *HistoryStorage) Radius(contentId []byte) *uint256.Int {
	if contentId == nil || !isEphemeralOfferType(contentId) {
		return hh.historyStorage.Radius(contentId)
	} else {
		return hh.ephemeralStorage.Radius(contentId)
	}
}

func (hh *HistoryStorage) Close() error {
	errHistory := hh.historyStorage.Close()
	errEphemeral := hh.ephemeralStorage.Close()

	if errHistory != nil {
		return errHistory
	} else if errEphemeral != nil {
		return errEphemeral
	}
	return nil
}

func isEphemeralOfferType(contentKey []byte) bool {
	return ContentType(contentKey[0]) == OfferEphemeralType
}
