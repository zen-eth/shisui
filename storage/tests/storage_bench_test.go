package tests

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/zen-eth/shisui/storage"
	ethpepple "github.com/zen-eth/shisui/storage/pebble"
	"github.com/zen-eth/shisui/storage/sqlite"
)

type testCase struct {
	name      string
	dataSize  int
	numOps    int
	batchSize int
}

var testCases = []testCase{
	{"SmallData", 100, 1000, 1},
	{"MediumData", 1024, 1000, 1},
	{"LargeData", 10240, 1000, 1},
	{"SmallBatch", 100, 1000, 100},
	{"MediumBatch", 1024, 1000, 100},
	{"LargeBatch", 10240, 1000, 100},
}

func generateTestData(size, count int) ([][]byte, [][]byte, [][]byte) {
	keys := make([][]byte, count)
	contentIds := make([][]byte, count)
	data := make([][]byte, count)
	for i := 0; i < count; i++ {
		keys[i] = make([]byte, 32)
		contentIds[i] = make([]byte, 32)
		data[i] = make([]byte, size)
		rand.Read(keys[i])
		rand.Read(contentIds[i])
		rand.Read(data[i])
	}
	return keys, contentIds, data
}

func BenchmarkStorageComparison(b *testing.B) {
	for _, tc := range testCases {
		keys, contentIds, data := generateTestData(tc.dataSize, tc.numOps)

		b.Run("Pebble_"+tc.name, func(b *testing.B) {
			dir, _ := os.MkdirTemp("", "pebble-bench-*")
			db, _ := ethpepple.NewDB(dir, 16, 16, "bench")
			storage, _ := ethpepple.NewStorage(storage.PortalStorageConfig{
				StorageCapacityMB: 1000,
				NodeId:            enode.ID{},
				NetworkName:       "bench",
			}, db)
			defer func() {
				db.Close()
				os.RemoveAll(dir)
			}()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < tc.numOps; j += tc.batchSize {
					for k := 0; k < tc.batchSize && j+k < tc.numOps; k++ {
						storage.Put(keys[j+k], contentIds[j+k], data[j+k])
					}
				}

				for j := 0; j < tc.numOps; j++ {
					storage.Get(keys[j], contentIds[j])
				}
			}
		})

		b.Run("SQLite_"+tc.name, func(b *testing.B) {
			dir, _ := os.MkdirTemp("", "sqlite-bench-*")
			db, _ := sqlite.NewDB(dir, "bench")
			storage, _ := sqlite.NewStorage(storage.PortalStorageConfig{
				StorageCapacityMB: 1000,
				NodeId:            enode.ID{},
				NetworkName:       "bench",
			}, db)
			defer func() {
				storage.Close()
				os.RemoveAll(dir)
			}()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < tc.numOps; j += tc.batchSize {
					for k := 0; k < tc.batchSize && j+k < tc.numOps; k++ {
						storage.Put(keys[j+k], contentIds[j+k], data[j+k])
					}
				}

				for j := 0; j < tc.numOps; j++ {
					storage.Get(keys[j], contentIds[j])
				}
			}
		})
	}
}
