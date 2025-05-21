package state

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/zen-eth/shisui/state/trie"
	"github.com/zen-eth/shisui/validation"
)

var _ validation.Validator = &StateValidator{}

type StateValidator struct {
	validationOracle validation.Oracle
}

func NewStateValidator(oracle validation.Oracle) *StateValidator {
	return &StateValidator{
		validationOracle: oracle,
	}
}

// ValidateContent implements validation.Validator.
func (s *StateValidator) ValidateContent(contentKey []byte, content []byte) error {
	keyType := contentKey[0]
	switch keyType {
	case AccountTrieNodeType:
		return s.validateAccountTrieNode(contentKey[1:], content)
	case ContractStorageTrieNodeType:
		return s.validateContractStorageTrieNode(contentKey[1:], content)
	case ContractByteCodeType:
		return s.validateContractByteCode(contentKey[1:], content)
	}
	return errors.New("unknown content type")
}

func (s *StateValidator) validateAccountTrieNode(contentKey []byte, content []byte) error {
	accountKey := &AccountTrieNodeKey{}
	err := accountKey.Deserialize(codec.NewDecodingReader(bytes.NewReader(contentKey), uint64(len(contentKey))))
	if err != nil {
		return err
	}
	accountData := &AccountTrieNodeWithProof{}
	err = accountData.Deserialize(codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
	if err != nil {
		return err
	}
	// get HeaderWithProof in history network
	stateRoot, err := s.validationOracle.GetBlockHeaderByHash(accountData.BlockHash[:])

	if err != nil {
		return err
	}
	err = validateNodeTrieProof(common.Bytes32(stateRoot.Root), accountKey.NodeHash, &accountKey.Path, &accountData.Proof)
	return err
}

func (s *StateValidator) validateContractStorageTrieNode(contentKey []byte, content []byte) error {
	contractStorageKey := &ContractStorageTrieNodeKey{}
	err := contractStorageKey.Deserialize(codec.NewDecodingReader(bytes.NewReader(contentKey), uint64(len(contentKey))))
	if err != nil {
		return err
	}
	contractProof := &ContractStorageTrieNodeWithProof{}
	err = contractProof.Deserialize(codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
	if err != nil {
		return err
	}
	stateRoot, err := s.validationOracle.GetBlockHeaderByHash(contractProof.BlockHash[:])
	if err != nil {
		return err
	}

	accountState, err := validateAccountState(common.Bytes32(stateRoot.Root), contractStorageKey.AddressHash, &contractProof.AccountProof)
	if err != nil {
		return err
	}
	err = validateNodeTrieProof(common.Bytes32(accountState.Root), contractStorageKey.NodeHash, &contractStorageKey.Path, &contractProof.StorageProof)
	return err
}

func (s *StateValidator) validateContractByteCode(contentKey []byte, content []byte) error {
	contractByteCodeKey := &ContractBytecodeKey{}
	err := contractByteCodeKey.Deserialize(codec.NewDecodingReader(bytes.NewReader(contentKey), uint64(len(contentKey))))
	if err != nil {
		return err
	}
	contractBytecodeWithProof := &ContractBytecodeWithProof{}
	err = contractBytecodeWithProof.Deserialize(codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
	if err != nil {
		return err
	}
	stateRoot, err := s.validationOracle.GetBlockHeaderByHash(contractBytecodeWithProof.BlockHash[:])
	if err != nil {
		return err
	}
	accountState, err := validateAccountState(common.Bytes32(stateRoot.Root), contractByteCodeKey.AddressHash, &contractBytecodeWithProof.AccountProof)
	if err != nil {
		return err
	}
	if !bytes.Equal(accountState.CodeHash, contractByteCodeKey.CodeHash[:]) {
		return errors.New("account state is invalid")
	}
	return nil
}

func validateTrieProof(rootHash common.Bytes32, path []byte, proof *TrieProof) (EncodedTrieNode, []byte, error) {
	if len(*proof) == 0 {
		return nil, nil, errors.New("proof should be empty")
	}
	firstNode := []EncodedTrieNode(*proof)[0]
	err := checkNodeHash(&firstNode, rootHash[:])
	if err != nil {
		return nil, nil, err
	}

	node := firstNode
	remainingPath := path

	for _, nextNode := range []EncodedTrieNode(*proof)[1:] {
		n, err := trie.DecodeTrieNode(nil, node)
		if err != nil {
			return nil, nil, err
		}
		hashNode, p, err := trie.TraverseTrieNode(n, remainingPath)
		if err != nil {
			return nil, nil, err
		}
		err = checkNodeHash(&nextNode, hashNode)

		if err != nil {
			return nil, nil, err
		}

		node = nextNode
		remainingPath = p
	}
	return node, remainingPath, nil
}

func checkNodeHash(node *EncodedTrieNode, hash []byte) error {
	nodeHash := node.NodeHash()
	if !bytes.Equal(nodeHash[:], hash) {
		return fmt.Errorf("node hash is not equal, expect: %v, actual: %v", hash, nodeHash)
	}
	return nil
}

func validateAccountState(rootHash common.Bytes32, addrrssHash common.Bytes32, proof *TrieProof) (*types.StateAccount, error) {
	path := make([]byte, 0, len(addrrssHash)*2)
	for _, item := range addrrssHash {
		before, after := unpackNibblePair(item)
		path = append(path, before, after)
	}
	lastProof, p, err := validateTrieProof(rootHash, path, proof)
	if err != nil {
		return nil, err
	}
	n, err := trie.DecodeTrieNode(nil, lastProof)
	if err != nil {
		return nil, err
	}
	stateBytes, _, err := trie.TraverseTrieNode(n, p)
	if err != nil {
		return nil, err
	}
	return types.FullAccount(stateBytes)
}

func validateNodeTrieProof(rootHash common.Bytes32, nodeHash common.Bytes32, path *Nibbles, proof *TrieProof) error {
	lastNode, p, err := validateTrieProof(rootHash, path.Nibbles, proof)
	if err != nil {
		return err
	}
	if len(p) != 0 {
		return errors.New("path is too long")
	}
	err = checkNodeHash(&lastNode, nodeHash[:])
	if err != nil {
		return err
	}
	return nil
}
