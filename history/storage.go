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

func (hs *HistoryStorage) setPrefix(key []byte) []byte {
	ret := append(hs.ephemeralPrefix, key...)
	return ret
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

func (hh *HistoryStorage) Get(contentKey []byte, contentId []byte) ([]byte, error) {
	if !isEphemeralOfferType(contentKey) {
		return hh.contentStorage.Get(contentKey, contentId)
	}
	distance := hh.setPrefix(contentKey)
	data, closer, err := hh.db.Get(distance)
	if err != nil {
		if errors.Is(err, cpebble.ErrNotFound) {
			return nil, storage.ErrContentNotFound
		}
		return nil, err
	}
	closer.Close()
	return data, nil
}

func (hh *HistoryStorage) Put(contentKey []byte, contentId []byte, content []byte) error {
	if !isEphemeralOfferType(contentKey) {
		return hh.contentStorage.Put(contentKey, contentId, content)
	}
	distance := hh.setPrefix(contentKey)
	newSize := hh.quantity.Add(1)

	batch := hh.db.NewBatch()
	err := batch.Set(distance, content, hh.writeOptions)
	if err != nil {
		return err
	}
	err = batch.Commit(hh.writeOptions)
	if err != nil {
		return err
	}

	if newSize > ephemeralHeadersMaxQuantity {
		err := hh.prune(newSize - ephemeralHeadersMaxQuantity)
		if err != nil {
			return err
		}
	}
	return nil
}

func (hh *HistoryStorage) prune(quantity uint64) error {
	//TODO
	//prune may consider reorgs
	//prune may store headers inside radius into history store
	hh.log.Debug("start pruning ephemeral")
	copyQuantity := quantity

	iter, err := hh.db.NewIter(nil)
	if err != nil {
		return err
	}

	batch := hh.db.NewBatch()
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

	hh.log.Debug("ephemeral prune finished", "pruneCount", copyQuantity-quantity)
	return nil
}

func (hh *HistoryStorage) Radius() *uint256.Int {
	return hh.contentStorage.Radius()
}

func (hh *HistoryStorage) Close() error {
	return hh.contentStorage.Close()
}

func isEphemeralOfferType(contentKey []byte) bool {
	return ContentType(contentKey[0]) == OfferEphemeralType
}
