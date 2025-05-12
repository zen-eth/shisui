package history

import (
	"github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"github.com/zen-eth/shisui/storage"
)

var _ storage.ContentStorage = &EphemeralStorage{}

type EphemeralStorage struct {
	db           *pebble.DB
	log          log.Logger
	writeOptions *pebble.WriteOptions
}

// NewEphemeralStorage creates a new instance of EphemeralStorage.
func NewEphemeralStorage(config storage.PortalStorageConfig, db *pebble.DB) *EphemeralStorage {
	return &EphemeralStorage{
		db:  db,
		log: log.New("ephemeral_storage", config.NetworkName),
		writeOptions: &pebble.WriteOptions{
			Sync: false,
		},
	}
}

// Get implements storage.ContentStorage.
// It retrieves the value associated with the given contentKey from the database.
// The contentId is not used in this implementation.
func (s *EphemeralStorage) Get(contentKey []byte, _ []byte) ([]byte, error) {
	value, closer, err := s.db.Get(contentKey)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return value, nil
}

// Put implements storage.ContentStorage.
// It stores the value associated with the given contentKey in the database.
// The contentId is not used in this implementation.
func (s *EphemeralStorage) Put(contentKey []byte, _ []byte, value []byte) error {
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(contentKey, value, s.writeOptions); err != nil {
		return err
	}
	return batch.Commit(s.writeOptions)
}

// Radius returns the storage radius.
// In this case, it is not supported and returns nil.
func (s *EphemeralStorage) Radius() *uint256.Int {
	s.log.Warn("Radius method is not supported in EphemeralStorage")
	return nil
}

// Close closes the database connection.
func (s *EphemeralStorage) Close() error {
	return s.db.Close()
}
