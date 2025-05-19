package history

import (
	ssz "github.com/ferranbt/fastssz"
	"github.com/protolambda/ztyp/tree"
)

// note: We changed the generated file since fastssz issues which can't be passed by the CI, so we commented the go:generate line
///go:generate sszgen --path history.go --exclude-objs EphemeralHeaderPayload,ContentType,ContentKey

type ContentType byte

const (
	BlockHeaderType          ContentType = 0x00
	BlockBodyType            ContentType = 0x01
	ReceiptsType             ContentType = 0x02
	BlockHeaderNumberType    ContentType = 0x03
	FindContentEphemeralType ContentType = 0x04
	OfferEphemeralType       ContentType = 0x05
)

type ContentKey struct {
	selector ContentType
	data     []byte
}

func NewContentKey(selector ContentType, hash []byte) *ContentKey {
	return &ContentKey{
		selector: selector,
		data:     hash,
	}
}

func (c *ContentKey) Encode() []byte {
	res := make([]byte, 0, len(c.data)+1)
	res = append(res, byte(c.selector))
	res = append(res, c.data...)
	return res
}

// Proof for EL BlockHeader before TheMerge / Paris
type BlockProofHistoricalHashesAccumulator struct {
	Proof [][]byte `ssz-size:"15,32"`
}

// Proof for EL BlockHeader from TheMerge until Capella (exclusive)
type BlockProofHistoricalRoots struct {
	BeaconBlockProof    [][]byte `ssz-size:"14,32" yaml:"historical_roots_proof"` // From TheMerge until Capella -> Bellatrix fork.
	BeaconBlockRoot     []byte   `ssz-size:"32" yaml:"beacon_block_root"`
	ExecutionBlockProof [][]byte `ssz-size:"11,32" yaml:"beacon_block_proof"` // Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
	Slot                uint64
}

func (b BlockProofHistoricalRoots) GetBeaconBlockProof() []tree.Root {
	roots := make([]tree.Root, 0)
	for _, proof := range b.BeaconBlockProof {
		roots = append(roots, tree.Root(proof))
	}
	return roots
}

func (b BlockProofHistoricalRoots) GetExecutionBlockProof() []tree.Root {
	roots := make([]tree.Root, 0)
	for _, proof := range b.ExecutionBlockProof {
		roots = append(roots, tree.Root(proof))
	}
	return roots
}

// Proof for EL BlockHeader for Capella
type BlockProofHistoricalSummariesCapella struct {
	BeaconBlockProof    [][]byte `ssz-size:"13,32"`
	BeaconBlockRoot     []byte   `ssz-size:"32"`
	ExecutionBlockProof [][]byte `ssz-size:"11,32"` // Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
	Slot                uint64
}

func (b BlockProofHistoricalSummariesCapella) GetBeaconBlockProof() []tree.Root {
	roots := make([]tree.Root, 0)
	for _, proof := range b.BeaconBlockProof {
		roots = append(roots, tree.Root(proof))
	}
	return roots
}

func (b BlockProofHistoricalSummariesCapella) GetExecutionBlockProof() []tree.Root {
	roots := make([]tree.Root, 0)
	for _, proof := range b.ExecutionBlockProof {
		roots = append(roots, tree.Root(proof))
	}
	return roots
}

// Proof for EL BlockHeader for Deneb
type BlockProofHistoricalSummariesDeneb struct {
	BeaconBlockProof    [][]byte `ssz-size:"13,32"`
	BeaconBlockRoot     []byte   `ssz-size:"32"`
	ExecutionBlockProof [][]byte `ssz-size:"12,32"`
	Slot                uint64
}

func (b BlockProofHistoricalSummariesDeneb) GetBeaconBlockProof() []tree.Root {
	roots := make([]tree.Root, 0)
	for _, proof := range b.BeaconBlockProof {
		roots = append(roots, tree.Root(proof))
	}
	return roots
}

func (b BlockProofHistoricalSummariesDeneb) GetExecutionBlockProof() []tree.Root {
	roots := make([]tree.Root, 0)
	for _, proof := range b.ExecutionBlockProof {
		roots = append(roots, tree.Root(proof))
	}
	return roots
}

type BlockHeaderWithProof struct {
	Header []byte `ssz-max:"8192"`
	Proof  []byte `ssz-max:"1024"`
}

type FindContentEphemeralHeadersKey struct {
	BlockHash     []byte `ssz-size:"32"`
	AncestorCount uint8
}

type EphemeralHeaderPayload struct {
	Payload [][]byte `ssz-max:"256,2048"`
}

// MarshalSSZ ssz marshals the EphemeralHeaderPayload object
func (e *EphemeralHeaderPayload) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(e)
}

// MarshalSSZTo ssz marshals the EphemeralHeaderPayload object to a target array
func (e *EphemeralHeaderPayload) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := 0

	// Field (0) 'Payload'
	if size := len(e.Payload); size > 256 {
		err = ssz.ErrListTooBigFn("EphemeralHeaderPayload.Payload", size, 256)
		return
	}
	{
		offset = 4 * len(e.Payload)
		for ii := 0; ii < len(e.Payload); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += len(e.Payload[ii])
		}
	}
	for ii := 0; ii < len(e.Payload); ii++ {
		if size := len(e.Payload[ii]); size > 2048 {
			err = ssz.ErrBytesLengthFn("EphemeralHeaderPayload.Payload[ii]", size, 2048)
			return
		}
		dst = append(dst, e.Payload[ii]...)
	}

	return
}

// UnmarshalSSZ ssz unmarshals the EphemeralHeaderPayload object
func (e *EphemeralHeaderPayload) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 4 {
		return ssz.ErrSize
	}

	// Field (0) 'Payload'
	{
		num, err := ssz.DecodeDynamicLength(buf, 256)
		if err != nil {
			return err
		}
		e.Payload = make([][]byte, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if len(buf) > 2048 {
				return ssz.ErrBytesLength
			}
			if cap(e.Payload[indx]) == 0 {
				e.Payload[indx] = make([]byte, 0, len(buf))
			}
			e.Payload[indx] = append(e.Payload[indx], buf...)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the EphemeralHeaderPayload object
func (e *EphemeralHeaderPayload) SizeSSZ() (size int) {
	size = 4

	// Field (0) 'Payload'
	for ii := 0; ii < len(e.Payload); ii++ {
		size += 4
		size += len(e.Payload[ii])
	}

	return
}

// HashTreeRoot ssz hashes the EphemeralHeaderPayload object
func (e *EphemeralHeaderPayload) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(e)
}

// HashTreeRootWith ssz hashes the EphemeralHeaderPayload object with a hasher
func (e *EphemeralHeaderPayload) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Payload'
	{
		subIndx := hh.Index()
		num := uint64(len(e.Payload))
		if num > 256 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range e.Payload {
			{
				elemIndx := hh.Index()
				byteLen := uint64(len(elem))
				if byteLen > 2048 {
					err = ssz.ErrIncorrectListSize
					return
				}
				hh.AppendBytes32(elem)
				hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 256)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the EphemeralHeaderPayload object
func (e *EphemeralHeaderPayload) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(e)
}

type OfferEphemeralHeaderKey struct {
	BlockHash []byte `ssz-size:"32"`
}

type OfferEphemeralHeader struct {
	Header []byte `ssz-max:"2048"`
}
