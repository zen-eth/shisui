package beacon

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/zen-eth/shisui/storage"
)

const BytesInMB uint64 = 1000 * 1000

// var portalStorageMetrics *portalwire.PortalStorageMetrics

type beaconStorageCache struct {
	rwLock           sync.RWMutex
	optimisticUpdate *ForkedLightClientOptimisticUpdate
	finalityUpdate   *ForkedLightClientFinalityUpdate
}

func (c *beaconStorageCache) GetOptimisticUpdate(slot uint64) *ForkedLightClientOptimisticUpdate {
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

func (c *beaconStorageCache) SetOptimisticUpdate(data *ForkedLightClientOptimisticUpdate) {
	c.rwLock.Lock()
	c.optimisticUpdate = data
	c.rwLock.Unlock()
}

func (c *beaconStorageCache) GetFinalityUpdate(slot uint64) *ForkedLightClientFinalityUpdate {
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

func (c *beaconStorageCache) SetFinalityUpdate(data *ForkedLightClientFinalityUpdate) {
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
	case LightClientBootstrap, HistoricalSummaries:
		data, _, err := bs.db.Get(contentId)
		if err != nil {
			return nil, handleNotFound(err)
		}
		return data, err
	case LightClientUpdate:
		lightClientUpdateKey := new(LightClientUpdateKey)
		err := lightClientUpdateKey.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return nil, err
		}
		res := make([]ForkedLightClientUpdate, 0)
		start := lightClientUpdateKey.StartPeriod
		for start < lightClientUpdateKey.StartPeriod+lightClientUpdateKey.Count {
			key := bs.getUint64Bytes(start)
			data, _, err := bs.db.Get(key)
			if err != nil {
				return nil, handleNotFound(err)
			}
			update := new(ForkedLightClientUpdate)
			err = update.Deserialize(bs.spec, codec.NewDecodingReader(bytes.NewReader(data), uint64(len(data))))
			if err != nil {
				return nil, err
			}
			res = append(res, *update)
			start++
		}
		var buf bytes.Buffer
		err = LightClientUpdateRange(res).Serialize(bs.spec, codec.NewEncodingWriter(&buf))
		return buf.Bytes(), err
	case LightClientFinalityUpdate:
		key := new(LightClientFinalityUpdateKey)
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
		key := new(LightClientOptimisticUpdateKey)
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
	}
	return nil, nil
}

func (bs *Storage) Put(contentKey []byte, contentId []byte, content []byte) error {
	length := uint64(len(contentId)) + uint64(len(content))
	bs.size.Add(length)
	batch := bs.db.NewBatch()
	var err error
	switch storage.ContentType(contentKey[0]) {
	case LightClientBootstrap, HistoricalSummaries:
		err = batch.Set(contentId, content, bs.writeOptions)
		if err != nil {
			return err
		}
		return batch.Commit(bs.writeOptions)
	case LightClientUpdate:
		lightClientUpdateKey := new(LightClientUpdateKey)
		err := lightClientUpdateKey.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return err
		}
		lightClientUpdateRange := new(LightClientUpdateRange)
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
		data := new(ForkedLightClientFinalityUpdate)
		err = data.Deserialize(bs.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		bs.cache.SetFinalityUpdate(data)
		return nil
	case LightClientOptimisticUpdate:
		data := new(ForkedLightClientOptimisticUpdate)
		err = data.Deserialize(bs.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		bs.cache.SetOptimisticUpdate(data)
		return nil
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
	buf := bs.bytePool.Get().(*[]byte)
	defer bs.bytePool.Put(buf)
	binary.BigEndian.PutUint64(*buf, value)
	return *buf
}

func handleNotFound(err error) error {
	if err == pebble.ErrNotFound {
		return storage.ErrContentNotFound
	}
	return err
}
