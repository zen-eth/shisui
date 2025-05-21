package beacon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/types/beacon"
)

const BytesInMB uint64 = 1000 * 1000

var historicalSummariesKey = []byte("historical_summaries")

type beaconStorageCache struct {
	rwLock           sync.RWMutex
	optimisticUpdate *beacon.ForkedLightClientOptimisticUpdate
	finalityUpdate   *beacon.ForkedLightClientFinalityUpdate
}

func (c *beaconStorageCache) GetOptimisticUpdate(slot uint64) *beacon.ForkedLightClientOptimisticUpdate {
	c.rwLock.RLock()
	optimisticUpdate := c.optimisticUpdate
	c.rwLock.RUnlock()
	if optimisticUpdate == nil {
		return nil
	}
	if optimisticUpdate.GetSignatureSlot() >= slot {
		return optimisticUpdate
	}
	return nil
}

func (c *beaconStorageCache) SetOptimisticUpdate(data *beacon.ForkedLightClientOptimisticUpdate) {
	c.rwLock.Lock()
	c.optimisticUpdate = data
	c.rwLock.Unlock()
}

func (c *beaconStorageCache) GetFinalityUpdate(slot uint64) *beacon.ForkedLightClientFinalityUpdate {
	c.rwLock.RLock()
	finalityUpdate := c.finalityUpdate
	c.rwLock.RUnlock()
	if finalityUpdate == nil {
		return nil
	}
	if finalityUpdate.GetBeaconSlot() >= slot {
		return finalityUpdate
	}
	return nil
}

func (c *beaconStorageCache) SetFinalityUpdate(data *beacon.ForkedLightClientFinalityUpdate) {
	c.rwLock.Lock()
	c.finalityUpdate = data
	c.rwLock.Unlock()
}

type Storage struct {
	storageCapacityInBytes uint64
	db                     *pebble.DB
	log                    log.Logger
	spec                   *common.Spec
	cache                  *beaconStorageCache
	size                   atomic.Uint64
	writeOptions           *pebble.WriteOptions
	bytePool               sync.Pool
}

var _ storage.ContentStorage = &Storage{}

func NewBeaconStorage(config storage.PortalStorageConfig, db *pebble.DB) (storage.ContentStorage, error) {
	bs := &Storage{
		storageCapacityInBytes: config.StorageCapacityMB * BytesInMB,
		db:                     db,
		log:                    log.New("beacon_storage"),
		spec:                   config.Spec,
		cache:                  &beaconStorageCache{},
		bytePool: sync.Pool{
			New: func() interface{} {
				out := make([]byte, 8)
				return &out
			},
		},
	}
	return bs, nil
}

func (bs *Storage) Get(contentKey []byte, contentId []byte) ([]byte, error) {
	switch storage.ContentType(contentKey[0]) {
	case LightClientBootstrap:
		data, closer, err := bs.db.Get(contentId)
		if err != nil {
			return nil, handleNotFound(err)
		}
		out := make([]byte, len(data))
		copy(out, data)
		if err := closer.Close(); err != nil {
			return nil, err
		}
		return out, nil
	case LightClientUpdate:
		lightClientUpdateKey := new(beacon.LightClientUpdateKey)
		err := lightClientUpdateKey.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return nil, err
		}
		res := make([]beacon.ForkedLightClientUpdate, 0)
		start := lightClientUpdateKey.StartPeriod
		for start < lightClientUpdateKey.StartPeriod+lightClientUpdateKey.Count {
			key := bs.getUint64Bytes(start)
			data, closer, err := bs.db.Get(key)
			if err != nil {
				return nil, handleNotFound(err)
			}
			update := new(beacon.ForkedLightClientUpdate)
			err = update.Deserialize(bs.spec, codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
			if err != nil {
				return nil, err
			}
			res = append(res, *update)
			start++
			if err := closer.Close(); err != nil {
				return nil, err
			}
		}
		var buf bytes.Buffer
		err = beacon.LightClientUpdateRange(res).Serialize(bs.spec, codec.NewEncodingWriter(&buf))
		return buf.Bytes(), err
	case LightClientFinalityUpdate:
		key := new(beacon.LightClientFinalityUpdateKey)
		err := key.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return nil, err
		}
		data := bs.cache.GetFinalityUpdate(key.FinalizedSlot)
		if data == nil {
			return nil, storage.ErrContentNotFound
		}
		var buf bytes.Buffer
		err = data.Serialize(bs.spec, codec.NewEncodingWriter(&buf))
		return buf.Bytes(), err
	case LightClientOptimisticUpdate:
		key := new(beacon.LightClientOptimisticUpdateKey)
		err := key.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return nil, err
		}
		data := bs.cache.GetOptimisticUpdate(key.OptimisticSlot)
		if data == nil {
			return nil, storage.ErrContentNotFound
		}
		var buf bytes.Buffer
		err = data.Serialize(bs.spec, codec.NewEncodingWriter(&buf))
		return buf.Bytes(), err
	case HistoricalSummaries:
		// return the historical summaries when epoch is bigger than contentKey[1:]
		data, closer, err := bs.db.Get(historicalSummariesKey)
		if err != nil {
			return nil, handleNotFound(err)
		}
		var out []byte
		if reverseCompare(data[:8], contentKey[1:]) != -1 {
			out = make([]byte, len(data[8:]))
			copy(out, data[8:])
		}
		if closeErr := closer.Close(); closeErr != nil {
			return nil, closeErr
		}
		if out != nil {
			return out, nil
		}
		return nil, storage.ErrContentNotFound
	}
	return nil, nil
}

func (bs *Storage) Put(contentKey []byte, contentId []byte, content []byte) error {
	length := uint64(len(contentId)) + uint64(len(content))
	bs.size.Add(length)
	batch := bs.db.NewBatch()
	var err error
	switch storage.ContentType(contentKey[0]) {
	case LightClientBootstrap:
		err = batch.Set(contentId, content, bs.writeOptions)
		if err != nil {
			return err
		}
		return batch.Commit(bs.writeOptions)
	case LightClientUpdate:
		lightClientUpdateKey := new(beacon.LightClientUpdateKey)
		err := lightClientUpdateKey.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return err
		}
		lightClientUpdateRange := new(beacon.LightClientUpdateRange)
		reader := codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content)))
		err = lightClientUpdateRange.Deserialize(bs.spec, reader)
		if err != nil {
			return err
		}
		for index, update := range *lightClientUpdateRange {
			var buf bytes.Buffer
			writer := codec.NewEncodingWriter(&buf)
			err := update.Serialize(bs.spec, writer)
			if err != nil {
				return err
			}
			period := lightClientUpdateKey.StartPeriod + uint64(index)
			key := bs.getUint64Bytes(period)
			err = batch.Set(key, buf.Bytes(), bs.writeOptions)
			if err != nil {
				return err
			}
		}
		return batch.Commit(bs.writeOptions)
	case LightClientFinalityUpdate:
		data := new(beacon.ForkedLightClientFinalityUpdate)
		err = data.Deserialize(bs.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		bs.cache.SetFinalityUpdate(data)
		return nil
	case LightClientOptimisticUpdate:
		data := new(beacon.ForkedLightClientOptimisticUpdate)
		err = data.Deserialize(bs.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		bs.cache.SetOptimisticUpdate(data)
		return nil
	case HistoricalSummaries:
		// contentKey is uint64 in bytes
		// key is a constant, value is contentKey[1:] + content
		data, closer, err := bs.db.Get(historicalSummariesKey)
		if errors.Is(err, pebble.ErrNotFound) {
			value := make([]byte, 0)
			value = append(value, contentKey[1:]...)
			value = append(value, content...)
			err = batch.Set(historicalSummariesKey, value, bs.writeOptions)
			if err != nil {
				return err
			}
			return batch.Commit(bs.writeOptions)
		}
		if err != nil {
			return err
		}

		epochBytes := data[:8]
		shouldUpdate := reverseCompare(contentKey[1:], epochBytes) == 1

		if closeErr := closer.Close(); closeErr != nil {
			return closeErr
		}

		if shouldUpdate {
			value := make([]byte, 0)
			value = append(value, contentKey[1:]...)
			value = append(value, content...)
			err = batch.Set(historicalSummariesKey, value, bs.writeOptions)
			if err != nil {
				return err
			}
			return batch.Commit(bs.writeOptions)
		}
	}
	return nil
}

// beacon network always returns the maximum distance
func (bs *Storage) Radius() *uint256.Int {
	return storage.MaxDistance
}

func (bs *Storage) Close() error {
	return bs.db.Close()
}

func (bs *Storage) getUint64Bytes(value uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	return buf
}

func handleNotFound(err error) error {
	if errors.Is(err, pebble.ErrNotFound) {
		return storage.ErrContentNotFound
	}
	return err
}

func reverseCompare(a, b []byte) int {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] > b[i] {
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
	}
	return 0
}
