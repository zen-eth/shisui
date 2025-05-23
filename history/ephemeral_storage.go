package history

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/types/history"
)

const maxAncestorCount uint8 = 255

var errInvalidAncestorCount = errors.New("invalid ancestor count")
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
// The contentKey is expected to be `FindContentEphemeralHeadersKey`.
// The resulting value is a serialized `EphemeralHeaderPayload`.
// The contentId is not used in this implementation.
func (s *EphemeralStorage) Get(contentKey []byte, _ []byte) ([]byte, error) {
	parsedKey := &history.FindContentEphemeralHeadersKey{}
	err := parsedKey.UnmarshalSSZ(contentKey[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal contentKey: %w", err)
	}

	if parsedKey.AncestorCount > maxAncestorCount {
		return nil, errInvalidAncestorCount
	}

	startBlockNumKeyBytes, numCloser, err := s.db.Get(parsedKey.BlockHash[:])
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, fmt.Errorf("block number key not found for hash %x: %w", parsedKey.BlockHash, err)
		}
		return nil, fmt.Errorf("failed to get block number key for hash %x: %w", parsedKey.BlockHash, err)
	}

	startBlockNumKey := make([]byte, len(startBlockNumKeyBytes))
	copy(startBlockNumKey, startBlockNumKeyBytes)
	if numCloser != nil {
		if numCloseErr := numCloser.Close(); numCloseErr != nil {
			return nil, fmt.Errorf("failed to close numCloser: %w", numCloseErr)
		}
	}

	initialActualBlockNum, err := decodeBlockNumber(startBlockNumKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode initial block number from key %x: %w", startBlockNumKey, err)
	}

	initialHeaderBytes, headerCloser, err := s.db.Get(startBlockNumKey)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, fmt.Errorf("header not found for start block number key %x (decoded: %d): %w", startBlockNumKey, initialActualBlockNum, err)
		}
		return nil, fmt.Errorf("failed to get header for start block number key %x: %w", startBlockNumKey, err)
	}

	initialHeader := make([]byte, len(initialHeaderBytes))
	copy(initialHeader, initialHeaderBytes)
	if headerCloser != nil {
		if headCloseErr := headerCloser.Close(); headCloseErr != nil {
			return nil, fmt.Errorf("failed to close headerCloser: %w", headCloseErr)
		}
	}

	collectedHeaders := make([][]byte, 0, 1+int(parsedKey.AncestorCount))
	collectedHeaders = append(collectedHeaders, initialHeader)
	lastSuccessfullyAddedBlockNum := initialActualBlockNum

	if parsedKey.AncestorCount > 0 {
		iterOpts := &pebble.IterOptions{}
		iter, err := s.db.NewIter(iterOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create iterator: %w", err)
		}
		defer iter.Close()

		if !iter.SeekGE(startBlockNumKey) {
			if iterErr := iter.Error(); iterErr != nil {
				return nil, fmt.Errorf("iterator error on SeekGE for known key %x: %w", startBlockNumKey, iterErr)
			}
			return nil, fmt.Errorf("SeekGE failed to find known key %x (iterator valid: %t)", startBlockNumKey, iter.Valid())
		}

		if !bytes.Equal(iter.Key(), startBlockNumKey) {
			if iterErr := iter.Error(); iterErr != nil {
				return nil, fmt.Errorf("iterator error after SeekGE found %x instead of known key %x: %w", iter.Key(), startBlockNumKey, iterErr)
			}
			return nil, fmt.Errorf("SeekGE for known key %x landed on a different key %x", startBlockNumKey, iter.Key())
		}

		for i := range int(parsedKey.AncestorCount) {
			if !iter.Prev() {
				if iterErr := iter.Error(); iterErr != nil {
					return nil, fmt.Errorf("iterator error on Prev(): %w", iterErr)
				}
				s.log.Debug("Iterator exhausted during Prev() for ancestors", "retrieved_count", i)
				break
			}

			currentIterKey := iter.Key()
			currentIterActualBlockNum, err := decodeBlockNumber(currentIterKey)
			if err != nil {
				s.log.Error("Failed to decode block number from iterator key", "key", currentIterKey, "err", err)
				break
			}

			if currentIterActualBlockNum != lastSuccessfullyAddedBlockNum-1 {
				s.log.Warn("Discontinuity found in ancestor chain.",
					"last_good_block", lastSuccessfullyAddedBlockNum,
					"found_block", currentIterActualBlockNum,
					"expected_block", lastSuccessfullyAddedBlockNum-1)
				break
			}

			ancestorHeader := make([]byte, len(iter.Value()))
			copy(ancestorHeader, iter.Value())
			collectedHeaders = append(collectedHeaders, ancestorHeader)
			lastSuccessfullyAddedBlockNum = currentIterActualBlockNum
		}
	}

	payload := &history.EphemeralHeaderPayload{
		Payload: collectedHeaders,
	}

	payloadBytes, err := payload.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return payloadBytes, nil
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

// decodeBlockNumber decodes a block number from the given byte slice.
func decodeBlockNumber(keyBytes []byte) (uint64, error) {
	if len(keyBytes) != 8 {
		return 0, fmt.Errorf("block number key bytes must be 8 bytes long, got %d", len(keyBytes))
	}
	return binary.BigEndian.Uint64(keyBytes), nil
}
