package history

import (
	"bytes"
	"errors"
	"fmt"
	"sync/atomic"

	cpebble "github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"github.com/zen-eth/shisui/storage"
)

const EPHEMERAL_PREFIX = 0x01

// Expects clients to store the full window of 8192 blocks of this data
// plus 100 slots for reorgs
// https://github.com/ethereum/portal-network-specs/blob/master/history/history-network.md#ephemeral-block-headers
var ephemeralHeadersMaxQuantity uint64 = 8192 + 100

var ErrMaxEphemeralReached = fmt.Errorf("max quantity of ephemeral reached")

type HistoryStorage struct {
	contentStorage  storage.ContentStorage
	log             log.Logger
	db              *cpebble.DB
	quantity        atomic.Uint64
	writeOptions    *cpebble.WriteOptions
	ephemeralPrefix []byte
}

func NewHistoyStorage(historyOriginal storage.ContentStorage, dbHistory *cpebble.DB) (storage.ContentStorage, error) {
	hh := &HistoryStorage{
		contentStorage:  historyOriginal,
		log:             log.New("storage", "histpry_ephemeral"),
		db:              dbHistory,
		writeOptions:    &cpebble.WriteOptions{Sync: false},
		ephemeralPrefix: []byte{EPHEMERAL_PREFIX},
	}

	hh.quantity.Store(0)

	return hh, nil
}

func (hs *HistoryStorage) Get(contentKey []byte, contentId []byte) ([]byte, error) {
	if !isEphemeralOfferType(contentKey) {
		return hs.contentStorage.Get(contentKey, contentId)
	}
	distance := hs.setPrefix(contentKey)
	data, closer, err := hs.db.Get(distance)
	if err != nil {
		if errors.Is(err, cpebble.ErrNotFound) {
			return nil, storage.ErrContentNotFound
		}
		return nil, err
	}
	closer.Close()
	return data, nil
}

func (hs *HistoryStorage) Put(contentKey []byte, contentId []byte, content []byte) error {
	if !isEphemeralOfferType(contentKey) {
		return hs.contentStorage.Put(contentKey, contentId, content)
	}
	distance := hs.setPrefix(contentKey)
	newSize := hs.quantity.Add(1)

	batch := hs.db.NewBatch()
	err := batch.Set(distance, content, hs.writeOptions)
	if err != nil {
		return err
	}
	err = batch.Commit(hs.writeOptions)
	if err != nil {
		return err
	}

	if newSize > ephemeralHeadersMaxQuantity {
		err := hs.prune(newSize - ephemeralHeadersMaxQuantity)
		if err != nil {
			return err
		}
	}
	return nil
}

func (hs *HistoryStorage) prune(quantity uint64) error {
	//TODO
	//prune may consider reorgs
	//prune may store headers inside radius into history store
	hs.log.Debug("start pruning ephemeral")
	copyQuantity := quantity

	iter, err := hs.db.NewIter(nil)
	if err != nil {
		return err
	}

	batch := hs.db.NewBatch()
	for iter.SeekPrefixGE([]byte{EPHEMERAL_PREFIX}); iter.Valid(); iter.Next() {
		if bytes.Equal(iter.Key(), storage.SizeKey) {
			continue
		}
		if quantity > 0 {
			err := batch.Delete(iter.Key(), nil)
			if err != nil {
				return err
			}
			quantity--
		} else {
			break
		}
	}
	err = batch.Commit(&cpebble.WriteOptions{Sync: true})
	if err != nil {
		return err
	}

	hs.log.Debug("ephemeral prune finished", "pruneCount", copyQuantity-quantity)
	return nil
}

func (hs *HistoryStorage) Radius() *uint256.Int {
	return hs.contentStorage.Radius()
}

func (hs *HistoryStorage) Close() error {
	return hs.contentStorage.Close()
}

func (hs *HistoryStorage) setPrefix(key []byte) []byte {
	ret := append(hs.ephemeralPrefix, key...)
	return ret
}

func isEphemeralOfferType(contentKey []byte) bool {
	return ContentType(contentKey[0]) == OfferEphemeralType
}
