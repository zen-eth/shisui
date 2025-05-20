package history

import (
	"github.com/holiman/uint256"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/types/history"
)

type Storage struct {
	eternalStorage   storage.ContentStorage
	ephemeralStorage *EphemeralStorage
}

func NewHistoryStorage(eternalStorage storage.ContentStorage, ephemeralStorage *EphemeralStorage) (storage.ContentStorage, error) {
	return &Storage{
		eternalStorage:   eternalStorage,
		ephemeralStorage: ephemeralStorage,
	}, nil
}

func (hs *Storage) Get(contentKey []byte, contentId []byte) ([]byte, error) {
	if isEphemeralOfferType(contentKey) {
		return hs.ephemeralStorage.Get(contentKey, contentId)
	} else {
		return hs.eternalStorage.Get(contentKey, contentId)
	}
}

func (hs *Storage) Put(contentKey []byte, contentId []byte, content []byte) error {
	if isEphemeralOfferType(contentKey) {
		return hs.ephemeralStorage.Put(contentKey, contentId, content)
	} else {
		return hs.eternalStorage.Put(contentKey, contentId, content)
	}
}

func (hs *Storage) Radius() *uint256.Int {
	// The radius is not supported in ephemeral storage.
	return hs.eternalStorage.Radius()
}

func (hs *Storage) Close() error {
	err := hs.ephemeralStorage.Close()
	if err != nil {
		return err
	}
	return hs.eternalStorage.Close()
}

func isEphemeralOfferType(contentKey []byte) bool {
	return history.ContentType(contentKey[0]) == history.OfferEphemeralType
}
