package history

import (
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/holiman/uint256"
	storage2 "github.com/optimism-java/shisui2/storage"
	"github.com/stretchr/testify/assert"
)

const nodeDataDir = "./unit_test"

func clearNodeData() {
	_ = os.Remove(fmt.Sprintf("%s/%s/%s", nodeDataDir, "history", sqliteName))
}

func genBytes(length int) []byte {
	res := make([]byte, length)
	for i := 0; i < length; i++ {
		res[i] = byte(i)
	}
	return res
}

func newContentStorage(storageCapacityInMB uint64, nodeId enode.ID, nodeDataDir string) (*ContentStorage, error) {
	db, err := NewDB(nodeDataDir, "history")
	if err != nil {
		return nil, err
	}
	hs, err := NewHistoryStorage(storage2.PortalStorageConfig{
		DB:                db,
		StorageCapacityMB: storageCapacityInMB,
		NodeId:            nodeId,
	})
	if err != nil {
		return nil, err
	}
	return hs.(*ContentStorage), nil
}

func TestBasicStorage(t *testing.T) {
	zeroNodeId := uint256.NewInt(0).Bytes32()
	contentStorage, err := newContentStorage(math.MaxUint32, zeroNodeId, nodeDataDir)
	assert.NoError(t, err)
	defer clearNodeData()
	defer contentStorage.Close()

	contentId := []byte("test")
	content := []byte("value")

	_, err = contentStorage.Get(nil, contentId)
	assert.Equal(t, storage2.ErrContentNotFound, err)

	pt := contentStorage.put(contentId, content)
	assert.NoError(t, pt.Err())

	val, err := contentStorage.Get(nil, contentId)
	assert.NoError(t, err)
	assert.Equal(t, content, val)

	count, err := contentStorage.ContentCount()
	assert.NoError(t, err)
	assert.Equal(t, count, uint64(1))

	size, err := contentStorage.Size()
	assert.NoError(t, err)
	assert.True(t, size > 0)

	unusedSize, err := contentStorage.UnusedSize()
	assert.NoError(t, err)

	usedSize, err := contentStorage.UsedSize()
	assert.NoError(t, err)
	assert.True(t, usedSize == size-unusedSize)
}

func TestDBSize(t *testing.T) {
	zeroNodeId := uint256.NewInt(0).Bytes32()
	contentStorage, err := newContentStorage(math.MaxUint32, zeroNodeId, nodeDataDir)
	assert.NoError(t, err)
	defer clearNodeData()
	defer contentStorage.Close()

	numBytes := 10000

	size1, err := contentStorage.Size()
	assert.NoError(t, err)
	putResult := contentStorage.put(uint256.NewInt(1).Bytes(), genBytes(numBytes))
	assert.Nil(t, putResult.Err())

	size2, err := contentStorage.Size()
	assert.NoError(t, err)
	putResult = contentStorage.put(uint256.NewInt(2).Bytes(), genBytes(numBytes))
	assert.NoError(t, putResult.Err())

	size3, err := contentStorage.Size()
	assert.NoError(t, err)
	putResult = contentStorage.put(uint256.NewInt(2).Bytes(), genBytes(numBytes))
	assert.NoError(t, putResult.Err())

	size4, err := contentStorage.Size()
	assert.NoError(t, err)
	usedSize, err := contentStorage.UsedSize()
	assert.NoError(t, err)

	assert.True(t, size2 > size1)
	assert.True(t, size3 > size2)
	assert.True(t, size4 == size3)
	assert.True(t, usedSize == size4)

	err = contentStorage.del(uint256.NewInt(2).Bytes())
	assert.NoError(t, err)
	err = contentStorage.del(uint256.NewInt(1).Bytes())
	assert.NoError(t, err)

	usedSize1, err := contentStorage.UsedSize()
	assert.NoError(t, err)
	size5, err := contentStorage.Size()
	assert.NoError(t, err)

	assert.True(t, size4 == size5)
	assert.True(t, usedSize1 < size5)

	err = contentStorage.ReclaimSpace()
	assert.NoError(t, err)

	usedSize2, err := contentStorage.UsedSize()
	assert.NoError(t, err)
	size6, err := contentStorage.Size()
	assert.NoError(t, err)

	assert.Equal(t, size1, size6)
	assert.Equal(t, usedSize2, size6)
}

func TestDBPruning(t *testing.T) {
	storageCapacity := uint64(1)

	zeroNodeId := uint256.NewInt(0).Bytes32()
	contentStorage, err := newContentStorage(storageCapacity, zeroNodeId, nodeDataDir)
	assert.NoError(t, err)
	defer clearNodeData()
	defer contentStorage.Close()

	furthestElement := uint256.NewInt(40)
	secondFurthest := uint256.NewInt(30)
	thirdFurthest := uint256.NewInt(20)

	numBytes := 100_000
	// test with private put method
	pt1 := contentStorage.put(uint256.NewInt(1).Bytes(), genBytes(numBytes))
	assert.NoError(t, pt1.Err())
	pt2 := contentStorage.put(thirdFurthest.Bytes(), genBytes(numBytes))
	assert.NoError(t, pt2.Err())
	pt3 := contentStorage.put(uint256.NewInt(3).Bytes(), genBytes(numBytes))
	assert.NoError(t, pt3.Err())
	pt4 := contentStorage.put(uint256.NewInt(10).Bytes(), genBytes(numBytes))
	assert.NoError(t, pt4.Err())
	pt5 := contentStorage.put(uint256.NewInt(5).Bytes(), genBytes(numBytes))
	assert.NoError(t, pt5.Err())
	pt6 := contentStorage.put(uint256.NewInt(11).Bytes(), genBytes(numBytes))
	assert.NoError(t, pt6.Err())
	pt7 := contentStorage.put(furthestElement.Bytes(), genBytes(40000))
	assert.NoError(t, pt7.Err())
	pt8 := contentStorage.put(secondFurthest.Bytes(), genBytes(30000))
	assert.NoError(t, pt8.Err())
	pt9 := contentStorage.put(uint256.NewInt(2).Bytes(), genBytes(numBytes*2))
	assert.NoError(t, pt9.Err())

	res, _ := contentStorage.GetLargestDistance()

	assert.Equal(t, res, uint256.NewInt(40))
	pt10 := contentStorage.put(uint256.NewInt(4).Bytes(), genBytes(132000))
	assert.NoError(t, pt10.Err())

	assert.False(t, pt1.Pruned())
	assert.False(t, pt2.Pruned())
	assert.False(t, pt3.Pruned())
	assert.False(t, pt4.Pruned())
	assert.False(t, pt5.Pruned())
	assert.False(t, pt6.Pruned())
	assert.False(t, pt7.Pruned())
	assert.False(t, pt8.Pruned())
	assert.False(t, pt9.Pruned())
	assert.True(t, pt10.Pruned())

	assert.Equal(t, pt10.PrunedCount(), 2)
	usedSize, err := contentStorage.UsedSize()
	assert.NoError(t, err)
	assert.True(t, usedSize < contentStorage.storageCapacityInBytes)

	_, err = contentStorage.Get(nil, furthestElement.Bytes())
	assert.Equal(t, storage2.ErrContentNotFound, err)

	_, err = contentStorage.Get(nil, secondFurthest.Bytes())
	assert.Equal(t, storage2.ErrContentNotFound, err)

	val, err := contentStorage.Get(nil, thirdFurthest.Bytes())
	assert.NoError(t, err)
	assert.NotNil(t, val)
}

func TestGetLargestDistance(t *testing.T) {
	storageCapacity := uint64(1)

	zeroNodeId := uint256.NewInt(0).Bytes32()
	contentStorage, err := newContentStorage(storageCapacity, zeroNodeId, nodeDataDir)
	assert.NoError(t, err)
	defer clearNodeData()
	defer contentStorage.Close()

	furthestElement := uint256.NewInt(40)
	secondFurthest := uint256.NewInt(30)

	pt7 := contentStorage.put(furthestElement.Bytes(), genBytes(2000))
	assert.NoError(t, pt7.Err())

	val, err := contentStorage.Get(nil, furthestElement.Bytes())
	assert.NoError(t, err)
	assert.NotNil(t, val)
	pt8 := contentStorage.put(secondFurthest.Bytes(), genBytes(2000))
	assert.NoError(t, pt8.Err())
	res, err := contentStorage.GetLargestDistance()
	assert.NoError(t, err)
	assert.Equal(t, furthestElement, res)
}

func TestSimpleForcePruning(t *testing.T) {
	storageCapacity := uint64(100_000)

	zeroNodeId := uint256.NewInt(0).Bytes32()
	contentStorage, err := newContentStorage(storageCapacity, zeroNodeId, nodeDataDir)
	assert.NoError(t, err)
	defer clearNodeData()
	defer contentStorage.Close()

	furthestElement := uint256.NewInt(40)
	secondFurthest := uint256.NewInt(30)
	third := uint256.NewInt(10)

	pt1 := contentStorage.put(furthestElement.Bytes(), genBytes(2000))
	assert.NoError(t, pt1.Err())

	pt2 := contentStorage.put(secondFurthest.Bytes(), genBytes(2000))
	assert.NoError(t, pt2.Err())

	pt3 := contentStorage.put(third.Bytes(), genBytes(2000))
	assert.NoError(t, pt3.Err())
	res, err := contentStorage.GetLargestDistance()
	assert.NoError(t, err)
	assert.Equal(t, furthestElement, res)

	err = contentStorage.ForcePrune(uint256.NewInt(20))
	assert.NoError(t, err)

	_, err = contentStorage.Get(nil, furthestElement.Bytes())
	assert.Equal(t, storage2.ErrContentNotFound, err)

	_, err = contentStorage.Get(nil, secondFurthest.Bytes())
	assert.Equal(t, storage2.ErrContentNotFound, err)

	_, err = contentStorage.Get(nil, third.Bytes())
	assert.NoError(t, err)
}

func TestForcePruning(t *testing.T) {
	const startCap = uint64(14_159_872)
	const endCapacity = uint64(5000_000)
	const amountOfItems = 10_000

	maxUint256 := uint256.MustFromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	nodeId := uint256.MustFromHex("0x30994892f3e4889d99deb5340050510d1842778acc7a7948adffa475fed51d6e").Bytes()
	content := genBytes(1000)

	storage, err := newContentStorage(startCap, enode.ID(nodeId), nodeDataDir)
	assert.NoError(t, err)
	defer clearNodeData()
	defer storage.Close()

	storage.storageCapacityInBytes = startCap

	increment := uint256.NewInt(0).Div(maxUint256, uint256.NewInt(amountOfItems))
	remainder := uint256.NewInt(0).Mod(maxUint256, uint256.NewInt(amountOfItems))

	id := uint256.NewInt(0)
	putCount := 0
	// id < maxUint256 - remainder
	for id.Cmp(uint256.NewInt(0).Sub(maxUint256, remainder)) == -1 {
		res := storage.put(id.Bytes(), content)
		assert.NoError(t, res.Err())
		id = id.Add(id, increment)
		putCount++
	}

	storage.storageCapacityInBytes = endCapacity

	oldDistance, err := storage.GetLargestDistance()
	assert.NoError(t, err)
	newDistance, err := storage.EstimateNewRadius(oldDistance)
	assert.NoError(t, err)
	assert.NotEqual(t, oldDistance.Cmp(newDistance), -1)
	err = storage.ForcePrune(newDistance)
	assert.NoError(t, err)

	var total int64
	err = storage.sqliteDB.QueryRow("SELECT count(*) FROM kvstore where greater(xor(key, (?1)), (?2)) = 1", storage.nodeId[:], newDistance.Bytes()).Scan(&total)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), total)
}
