package history

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"github.com/zen-eth/shisui/storage"
)

type EphemeralStorage struct {
	maxCapacityQuantity uint64
	db                  *pebble.DB
	log                 log.Logger
	size                atomic.Uint64
	writeOptions        *pebble.WriteOptions
	bytePool            sync.Pool
}

func NewEphemeralStorage(db *pebble.DB) (storage.ContentStorage, error) {
	es := &EphemeralStorage{
		maxCapacityQuantity: uint64(ephemeralHeadersMaxQuantity),
		db:                  db,
		log:                 log.New("ephemeral_storage"),
		bytePool: sync.Pool{
			New: func() interface{} {
				out := make([]byte, 8)
				return &out
			},
		},
	}
	return es, nil
}

func (es *EphemeralStorage) Get(contentKey []byte, contentId []byte) ([]byte, error) {
	data, _, err := es.db.Get(contentId)
	if err != nil {
		return nil, handleNotFound(err)
	}
	return data, err
}

func (es *EphemeralStorage) Put(contentKey []byte, contentId []byte, content []byte) error {
	newSize := es.size.Add(1)
	batch := es.db.NewBatch()
	err := batch.Set(contentId, content, es.writeOptions)
	if err != nil {
		return err
	}
	err = batch.Commit(es.writeOptions)
	if err != nil {
		return err
	}

	if newSize > es.maxCapacityQuantity {
		err := es.prune(newSize - es.maxCapacityQuantity)
		if err != nil {
			return err
		}
	}

	return nil
}

func (es *EphemeralStorage) prune(quantity uint64) error {
	//TODO
	//prune may consider reorgs
	//prune may store headers inside radius into history store
	es.log.Debug("start pruning ephemeral")
	copyQuantity := quantity

	iter, err := es.db.NewIter(nil)
	if err != nil {
		return err
	}

	batch := es.db.NewBatch()
	for iter.First(); iter.Valid(); iter.Next() {
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
	err = batch.Commit(&pebble.WriteOptions{Sync: true})
	if err != nil {
		return err
	}

	es.log.Debug("ephemeral prune finished", "pruneCount", copyQuantity)
	return nil
}

// ephemeral storage always returns the maximum distance
func (es *EphemeralStorage) Radius() *uint256.Int {
	return storage.MaxDistance
}

func (es *EphemeralStorage) Close() error {
	return es.db.Close()
}

func handleNotFound(err error) error {
	if errors.Is(err, pebble.ErrNotFound) {
		return storage.ErrContentNotFound
	}
	return err
}
