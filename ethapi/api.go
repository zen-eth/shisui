package ethapi

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/zen-eth/shisui/history"
	"github.com/zen-eth/shisui/storage"
)

var errParameterNotImplemented = errors.New("parameter not implemented")

// marshalReceipt marshals a transaction receipt into a JSON object.
func marshalReceipt(receipt *types.Receipt, blockHash common.Hash, blockNumber uint64, signer types.Signer, tx *types.Transaction, txIndex int) map[string]interface{} {
	from, _ := types.Sender(signer, tx)

	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   tx.Hash(),
		"transactionIndex":  hexutil.Uint64(txIndex),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
		"type":              hexutil.Uint(tx.Type()),
		"effectiveGasPrice": (*hexutil.Big)(receipt.EffectiveGasPrice),
	}

	// Assign receipt status or post state.
	if len(receipt.PostState) > 0 {
		fields["root"] = hexutil.Bytes(receipt.PostState)
	} else {
		fields["status"] = hexutil.Uint(receipt.Status)
	}
	if receipt.Logs == nil {
		fields["logs"] = []*types.Log{}
	}

	if tx.Type() == types.BlobTxType {
		fields["blobGasUsed"] = hexutil.Uint64(receipt.BlobGasUsed)
		fields["blobGasPrice"] = (*hexutil.Big)(receipt.BlobGasPrice)
	}

	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields
}

type API struct {
	History *history.Network
	ChainID *big.Int
}

func (p *API) ChainId() hexutil.Uint64 {
	return (hexutil.Uint64)(p.ChainID.Uint64())
}

func (p *API) GetBlockByHash(hash common.Hash, fullTransactions bool) (map[string]interface{}, error) {
	blockNrOrHash := rpc.BlockNumberOrHashWithHash(hash, false)
	return p.getBlock(blockNrOrHash, fullTransactions)
}

func (p *API) GetBlockByNumber(number rpc.BlockNumber, fullTransactions bool) (map[string]interface{}, error) {
	blockNrOrHash := rpc.BlockNumberOrHashWithNumber(number)
	return p.getBlock(blockNrOrHash, fullTransactions)
}

func (p *API) getBlock(blockNrOrHash rpc.BlockNumberOrHash, fullTransactions bool) (map[string]interface{}, error) {
	var blockHeader *types.Header
	var err error

	number, ok := blockNrOrHash.Number()
	if ok {
		blockHeader, err = p.History.GetBlockHeaderByNumber(uint64(number.Int64()))
		// handle content not foud, must return NULL
		if errors.Is(err, storage.ErrContentNotFound) {
			log.Error("content not found error getting block header with number", "number", uint64(number.Int64()), "err", err)
			return nil, nil
		}
		if err != nil {
			log.Error("error getting block header with number", "number", uint64(number.Int64()), "err", err)
			return nil, err
		}
	} else {
		hash, _ := blockNrOrHash.Hash()
		blockHeader, err = p.History.GetBlockHeader(hash.Bytes())
		// handle content not foud, must return NULL
		if errors.Is(err, storage.ErrContentNotFound) {
			log.Error("content not found error getting block header with hash", "hash", hash, "err", err)
			return nil, nil
		}
		if err != nil {
			log.Error("error getting block header with hash", "hash", hash, "err", err)
			return nil, err
		}
	}

	blockBody, err := p.History.GetBlockBody(blockHeader.Hash().Bytes())
	if err != nil {
		log.Error("error getting block body with hash", "hash", blockHeader.Hash(), "err", err)
		return nil, err
	}

	block := types.NewBlockWithHeader(blockHeader).WithBody(*blockBody)
	// static configuration of Config, currently only mainnet implemented
	return RPCMarshalBlock(block, true, fullTransactions, params.MainnetChainConfig), nil
}

func (p *API) GetBlockReceipts(blockNrOrHash rpc.BlockNumberOrHash) ([]map[string]interface{}, error) {
	hash, isHhash := blockNrOrHash.Hash()
	if !isHhash {
		return nil, errParameterNotImplemented
	}

	blockReceipts, err := p.History.GetReceipts(hash.Bytes())
	if err != nil {
		log.Error("error getting receipts body with hash", "hash", hash, "err", err)
		return nil, err
	}

	blockBody, err := p.History.GetBlockBody(hash.Bytes())
	if err != nil {
		log.Error("error getting block body with hash", "hash", hash, "err", err)
		return nil, err
	}

	blockHeader, err := p.History.GetBlockHeader(hash.Bytes())
	if err != nil {
		log.Error("error getting header body with hash", "hash", hash, "err", err)
		return nil, err
	}

	txs := blockBody.Transactions
	if len(txs) != len(blockReceipts) {
		return nil, fmt.Errorf("receipts length mismatch: %d vs %d", len(txs), len(blockReceipts))
	}

	// Derive the sender.
	signer := types.MakeSigner(params.MainnetChainConfig, blockHeader.Number, blockHeader.Time)

	result := make([]map[string]interface{}, len(blockReceipts))
	for i, receipt := range blockReceipts {
		result[i] = marshalReceipt(receipt, blockHeader.Hash(), blockHeader.Number.Uint64(), signer, txs[i], i)
	}

	return result, nil
}

func (p *API) GetBlockTransactionCountByHash(hash common.Hash) *hexutil.Uint {
	blockNrOrHash := rpc.BlockNumberOrHashWithHash(hash, false)
	return p.getBlockTransactionCount(blockNrOrHash)
}

func (p *API) GetBlockTransactionCountByNumber(number rpc.BlockNumber) *hexutil.Uint {
	blockNrOrHash := rpc.BlockNumberOrHashWithNumber(number)
	return p.getBlockTransactionCount(blockNrOrHash)
}

func (p *API) getBlockTransactionCount(blockNrOrHash rpc.BlockNumberOrHash) *hexutil.Uint {
	var blockHeader *types.Header
	var err error
	var hash common.Hash

	number, ok := blockNrOrHash.Number()
	if ok {
		blockHeader, err = p.History.GetBlockHeaderByNumber(uint64(number.Int64()))
		if err != nil {
			log.Error("error getting block header with number", "number", uint64(number.Int64()), "err", err)
			return nil
		}
		hash = blockHeader.Hash()
	} else {
		hash, _ = blockNrOrHash.Hash()
	}

	blockBody, err := p.History.GetBlockBody(hash.Bytes())
	if err != nil {
		log.Error("error getting block body with hash", "hash", hash, "err", err)
		return nil
	}

	n := hexutil.Uint(len(blockBody.Transactions))
	return &n
}

func (p *API) GetUncleCountByBlockHash(hash common.Hash) *hexutil.Uint {
	blockNrOrHash := rpc.BlockNumberOrHashWithHash(hash, false)
	return p.getUncleCount(blockNrOrHash)
}

func (p *API) GetUncleCountByBlockNumber(number rpc.BlockNumber) *hexutil.Uint {
	blockNrOrHash := rpc.BlockNumberOrHashWithNumber(number)
	return p.getUncleCount(blockNrOrHash)
}

func (p *API) getUncleCount(blockNrOrHash rpc.BlockNumberOrHash) *hexutil.Uint {
	var blockHeader *types.Header
	var err error
	var hash common.Hash

	number, ok := blockNrOrHash.Number()
	if ok {
		blockHeader, err = p.History.GetBlockHeaderByNumber(uint64(number.Int64()))
		if err != nil {
			log.Error("error getting block header with number", "number", uint64(number.Int64()), "err", err)
			return nil
		}
		hash = blockHeader.Hash()
	} else {
		hash, _ = blockNrOrHash.Hash()
	}

	blockBody, err := p.History.GetBlockBody(hash.Bytes())
	if err != nil {
		log.Error("error getting block body with hash", "hash", hash, "err", err)
		return nil
	}

	n := hexutil.Uint(len(blockBody.Uncles))
	return &n
}
