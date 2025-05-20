package history

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/panjf2000/ants/v2"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/zen-eth/shisui/portalwire"
	"github.com/zen-eth/shisui/storage"
	"github.com/zen-eth/shisui/types/history"
	"github.com/zen-eth/shisui/validation"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

var (
	ErrWithdrawalHashIsNotEqual = errors.New("withdrawals hash is not equal")
	ErrTxHashIsNotEqual         = errors.New("tx hash is not equal")
	ErrUnclesHashIsNotEqual     = errors.New("uncles hash is not equal")
	ErrReceiptsHashIsNotEqual   = errors.New("receipts hash is not equal")
	ErrContentOutOfRange        = errors.New("content out of range")
	ErrHeaderWithProofIsInvalid = errors.New("header proof is invalid")
	ErrInvalidBlockHash         = errors.New("invalid block hash")
	ErrInvalidBlockNumber       = errors.New("invalid block number")
	ErrInternalError            = errors.New("internal error")
)

var emptyReceiptHash = hexutil.MustDecode("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

var antsPool, _ = ants.NewPool(100, ants.WithNonblocking(true))

type Network struct {
	portalProtocol *portalwire.PortalProtocol
	closeCtx       context.Context
	closeFunc      context.CancelFunc
	log            log.Logger
	spec           *common.Spec
	validator      validation.Validator
}

func NewHistoryNetwork(portalProtocol *portalwire.PortalProtocol, validator validation.Validator) *Network {
	ctx, cancel := context.WithCancel(context.Background())
	return &Network{
		portalProtocol: portalProtocol,
		closeCtx:       ctx,
		closeFunc:      cancel,
		log:            log.New("sub-protocol", "history"),
		spec:           configs.Mainnet,
		validator:      validator,
	}
}

func (h *Network) Start() error {
	err := h.portalProtocol.Start()
	if err != nil {
		return err
	}
	go h.processContentLoop(h.closeCtx)
	h.log.Debug("history network start successfully")
	return nil
}

func (h *Network) Stop() {
	h.closeFunc()
	h.portalProtocol.Stop()
}

func (h *Network) GetBlockHeader(blockHash []byte) (*types.Header, error) {
	contentKey := history.NewContentKey(history.BlockHeaderType, blockHash).Encode()
	contentId := h.portalProtocol.ToContentId(contentKey)
	h.log.Trace("contentKey convert to contentId", "contentKey", hexutil.Encode(contentKey), "contentId", hexutil.Encode(contentId))

	res, err := h.portalProtocol.Get(contentKey, contentId)
	// other error
	if err != nil && !errors.Is(err, storage.ErrContentNotFound) {
		return nil, err
	}
	// no error
	if err == nil {
		headerWithProof, err := history.DecodeHeaderWithProof(res)
		if err != nil {
			return nil, err
		}
		return headerWithProof.Header, err
	}
	// no content in local storage
	content, _, err := h.portalProtocol.ContentLookup(contentKey, contentId)
	if err != nil {
		h.log.Error("getBlockHeader failed", "contentKey", hexutil.Encode(contentKey), "err", err)
		return nil, ErrInternalError
	}

	err = h.validator.ValidateContent(contentKey, content)
	if err != nil {
		h.log.Error("verifyHeader failed", "contentKey", contentKey, "err", err)
		return nil, ErrInternalError
	}
	headerWithProof, err := history.DecodeHeaderWithProof(content)

	if err != nil {
		h.log.Error("decodeBlockHeaderWithProof failed", "content", hexutil.Encode(content), "err", err)
		return nil, ErrInternalError
	}

	err = h.portalProtocol.Put(contentKey, contentId, content)
	if err != nil {
		h.log.Error("failed to store content in getBlockHeader", "contentKey", hexutil.Encode(contentKey), "err", err)
	}
	return headerWithProof.Header, nil
}

func (h *Network) GetBlockBody(blockHash []byte) (*types.Body, error) {
	contentKey := history.NewContentKey(history.BlockBodyType, blockHash).Encode()
	contentId := h.portalProtocol.ToContentId(contentKey)

	res, err := h.portalProtocol.Get(contentKey, contentId)
	// other error
	// TODO maybe use nil res to replace the ErrContentNotFound
	if err != nil && !errors.Is(err, storage.ErrContentNotFound) {
		return nil, err
	}
	// no error
	if err == nil {
		body, err := DecodePortalBlockBodyBytes(res)
		return body, err
	}
	// no content in local storage

	content, _, err := h.portalProtocol.ContentLookup(contentKey, contentId)
	if err != nil {
		h.log.Error("get block body failed", "contentKey", hexutil.Encode(contentKey), "err", err)
		return nil, ErrInternalError
	}
	err = h.validator.ValidateContent(contentKey, content)
	if err != nil {
		h.log.Error("validateBlockBody failed", "header", "err", err)
		return nil, ErrInternalError
	}

	body, err := DecodePortalBlockBodyBytes(content)
	if err != nil {
		h.log.Error("decodePortalBlockBodyBytes failed", "content", hexutil.Encode(content), "err", err)
		return nil, ErrInternalError
	}

	err = h.portalProtocol.Put(contentKey, contentId, content)
	if err != nil {
		h.log.Error("failed to store content in getBlockBody", "contentKey", hexutil.Encode(contentKey), "err", err)
	}
	return body, nil
}

func (h *Network) GetReceipts(blockHash []byte) ([]*types.Receipt, error) {
	contentKey := history.NewContentKey(history.ReceiptsType, blockHash).Encode()
	contentId := h.portalProtocol.ToContentId(contentKey)

	res, err := h.portalProtocol.Get(contentKey, contentId)
	// other error
	if err != nil && !errors.Is(err, storage.ErrContentNotFound) {
		return nil, err
	}
	// no error
	if err == nil {
		portalReceipte := new(PortalReceipts)
		err := portalReceipte.UnmarshalSSZ(res)
		if err != nil {
			return nil, err
		}
		receipts, err := FromPortalReceipts(portalReceipte)
		return receipts, err
	}
	// no content in local storage
	content, _, err := h.portalProtocol.ContentLookup(contentKey, contentId)
	if err != nil {
		h.log.Error("getReceipts failed", "contentKey", hexutil.Encode(contentKey), "err", err)
		return nil, ErrInternalError
	}
	err = h.validator.ValidateContent(contentKey, content)
	if err != nil {
		h.log.Error("validate receipts failed", "err", err)
		return nil, ErrInternalError
	}
	receipts, err := DecodeReceipts(content)
	if err != nil {
		h.log.Error("decode receipts failed", "err", err)
		return nil, ErrInternalError
	}
	err = h.portalProtocol.Put(contentKey, contentId, content)
	if err != nil {
		h.log.Error("failed to store content in getReceipts", "contentKey", hexutil.Encode(contentKey), "err", err)
	}
	return receipts, nil
}

func (h *Network) processContentLoop(ctx context.Context) {
	contentChan := h.portalProtocol.GetContent()
	for {
		select {
		case <-ctx.Done():
			return
		case contentElement := <-contentChan:
			err := antsPool.Submit(func() {
				err := h.validateContents(contentElement.ContentKeys, contentElement.Contents)
				if err != nil {
					h.log.Error("validate contents failed", "err", err)
					return
				}
				go func() {
					var gossippedNum int
					gossippedNum, err := h.portalProtocol.Gossip(&contentElement.Node, contentElement.ContentKeys, contentElement.Contents)
					h.log.Trace("gossippedNum", "gossippedNum", gossippedNum)
					if err != nil {
						h.log.Error("gossip failed", "err", err)
					}
				}()
			})
			if err != nil {
				h.log.Warn("submit to ants pool failed", "err", err)
			}
		}
	}
}

func (h *Network) validateContents(contentKeys [][]byte, contents [][]byte) error {
	for i, content := range contents {
		contentKey := contentKeys[i]
		contentId := h.portalProtocol.ToContentId(contentKey)
		_, err := h.portalProtocol.Get(contentKey, contentId)
		// exist in db
		if err == nil {
			continue
		}
		err = h.validator.ValidateContent(contentKey, content)
		if err != nil {
			return fmt.Errorf("content validate failed with content key %x, err is %w", contentKey, err)
		}
		_ = h.portalProtocol.Put(contentKey, contentId, content)
	}
	return nil
}

func ValidateBlockBodyBytes(bodyBytes []byte, header *types.Header) (*types.Body, error) {
	// TODO check shanghai, pos and legacy block
	body, err := DecodePortalBlockBodyBytes(bodyBytes)
	if err != nil {
		return nil, err
	}
	err = validateBlockBody(body, header)
	return body, err
}

func DecodePortalBlockBodyBytes(bodyBytes []byte) (*types.Body, error) {
	blockBodyShanghai := new(PortalBlockBodyShanghai)
	err := blockBodyShanghai.UnmarshalSSZ(bodyBytes)
	if err == nil {
		return FromPortalBlockBodyShanghai(blockBodyShanghai)
	}

	blockBodyLegacy := new(BlockBodyLegacy)
	err = blockBodyLegacy.UnmarshalSSZ(bodyBytes)
	if err == nil {
		return FromBlockBodyLegacy(blockBodyLegacy)
	}
	return nil, errors.New("all portal block body decodings failed")
}

func validateBlockBody(body *types.Body, header *types.Header) error {
	if hash := types.CalcUncleHash(body.Uncles); !bytes.Equal(hash[:], header.UncleHash.Bytes()) {
		return ErrUnclesHashIsNotEqual
	}

	if hash := types.DeriveSha(types.Transactions(body.Transactions), trie.NewStackTrie(nil)); !bytes.Equal(hash[:], header.TxHash.Bytes()) {
		return ErrTxHashIsNotEqual
	}
	if body.Withdrawals == nil {
		return nil
	}
	if hash := types.DeriveSha(types.Withdrawals(body.Withdrawals), trie.NewStackTrie(nil)); !bytes.Equal(hash[:], header.WithdrawalsHash.Bytes()) {
		return ErrWithdrawalHashIsNotEqual
	}
	return nil
}

// EncodeBlockBody encode types.Body to ssz bytes
func EncodeBlockBody(body *types.Body) ([]byte, error) {
	if len(body.Withdrawals) > 0 {
		blockShanghai, err := toPortalBlockBodyShanghai(body)
		if err != nil {
			return nil, err
		}
		return blockShanghai.MarshalSSZ()
	} else {
		legacyBlock, err := toBlockBodyLegacy(body)
		if err != nil {
			return nil, err
		}
		return legacyBlock.MarshalSSZ()
	}
}

// toPortalBlockBodyShanghai convert types.Body to PortalBlockBodyShanghai
func toPortalBlockBodyShanghai(b *types.Body) (*PortalBlockBodyShanghai, error) {
	legacy, err := toBlockBodyLegacy(b)
	if err != nil {
		return nil, err
	}
	withdrawals := make([][]byte, 0, len(b.Withdrawals))
	for _, w := range b.Withdrawals {
		b, err := rlp.EncodeToBytes(w)
		if err != nil {
			return nil, err
		}
		withdrawals = append(withdrawals, b)
	}
	return &PortalBlockBodyShanghai{Transactions: legacy.Transactions, Uncles: legacy.Uncles, Withdrawals: withdrawals}, nil
}

// toBlockBodyLegacy convert types.Body to BlockBodyLegacy
func toBlockBodyLegacy(b *types.Body) (*BlockBodyLegacy, error) {
	txs := make([][]byte, 0, len(b.Transactions))

	for _, tx := range b.Transactions {
		txBytes, err := rlp.EncodeToBytes(tx)
		if err != nil {
			return nil, err
		}
		txs = append(txs, txBytes)
	}

	uncleBytes, err := rlp.EncodeToBytes(b.Uncles)
	if err != nil {
		return nil, err
	}
	return &BlockBodyLegacy{Uncles: uncleBytes, Transactions: txs}, err
}

// FromPortalBlockBodyShanghai convert PortalBlockBodyShanghai to types.Body
func FromPortalBlockBodyShanghai(b *PortalBlockBodyShanghai) (*types.Body, error) {
	transactions := make([]*types.Transaction, 0, len(b.Transactions))
	for _, t := range b.Transactions {
		tran := new(types.Transaction)
		err := tran.UnmarshalBinary(t)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, tran)
	}
	uncles := make([]*types.Header, 0, len(b.Uncles))
	err := rlp.DecodeBytes(b.Uncles, &uncles)
	withdrawals := make([]*types.Withdrawal, 0, len(b.Withdrawals))
	for _, w := range b.Withdrawals {
		withdrawal := new(types.Withdrawal)
		err := rlp.DecodeBytes(w, withdrawal)
		if err != nil {
			return nil, err
		}
		withdrawals = append(withdrawals, withdrawal)
	}
	return &types.Body{
		Uncles:       uncles,
		Transactions: transactions,
		Withdrawals:  withdrawals,
	}, err
}

// FromBlockBodyLegacy convert BlockBodyLegacy to types.Body
func FromBlockBodyLegacy(b *BlockBodyLegacy) (*types.Body, error) {
	transactions := make([]*types.Transaction, 0, len(b.Transactions))
	for _, t := range b.Transactions {
		tran := new(types.Transaction)
		err := tran.UnmarshalBinary(t)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, tran)
	}
	uncles := make([]*types.Header, 0, len(b.Uncles))
	err := rlp.DecodeBytes(b.Uncles, &uncles)
	return &types.Body{
		Uncles:       uncles,
		Transactions: transactions,
	}, err
}

// FromPortalReceipts convert PortalReceipts to types.Receipt
func FromPortalReceipts(r *PortalReceipts) ([]*types.Receipt, error) {
	res := make([]*types.Receipt, 0, len(r.Receipts))
	for _, reci := range r.Receipts {
		recipt := new(types.Receipt)
		err := recipt.UnmarshalBinary(reci)
		if err != nil {
			return nil, err
		}
		res = append(res, recipt)
	}
	return res, nil
}

func DecodeReceipts(receiptBytes []byte) ([]*types.Receipt, error) {
	portalReceipts := new(PortalReceipts)
	err := portalReceipts.UnmarshalSSZ(receiptBytes)
	if err != nil {
		return nil, err
	}

	receipts, err := FromPortalReceipts(portalReceipts)
	if err != nil {
		return nil, err
	}
	return receipts, nil
}

func ValidatePortalReceiptsBytes(receiptBytes, receiptsRoot []byte) ([]*types.Receipt, error) {
	receipts, err := DecodeReceipts(receiptBytes)
	if err != nil {
		return nil, err
	}

	root := types.DeriveSha(types.Receipts(receipts), trie.NewStackTrie(nil))

	if !bytes.Equal(root[:], receiptsRoot) {
		return nil, errors.New("receipt root is not equal to the header.ReceiptHash")
	}
	return receipts, nil
}

func EncodeReceipts(receipts []*types.Receipt) ([]byte, error) {
	portalReceipts, err := ToPortalReceipts(receipts)
	if err != nil {
		return nil, err
	}
	return portalReceipts.MarshalSSZ()
}

// ToPortalReceipts convert types.Receipt to PortalReceipts
func ToPortalReceipts(receipts []*types.Receipt) (*PortalReceipts, error) {
	res := make([][]byte, 0, len(receipts))
	for _, r := range receipts {
		b, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return &PortalReceipts{Receipts: res}, nil
}
