package beacon

import (
	"encoding/binary"
	"errors"

	"github.com/protolambda/zrnt/eth2/beacon/altair"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/tree"
)

const MaxRequestLightClientUpdates = 128

var (
	Bellatrix common.ForkDigest = [4]byte{0x0, 0x0, 0x0, 0x0}
	Capella   common.ForkDigest = [4]byte{0xbb, 0xa4, 0xda, 0x96}
	Deneb     common.ForkDigest = [4]byte{0x6a, 0x95, 0xa1, 0xa9}
)

// note: We changed the generated file since fastssz issues which can't be passed by the CI, so we commented the go:generate line
///go:generate sszgen --path types.go --exclude-objs ForkedLightClientBootstrap,ForkedLightClientUpdate,LightClientUpdateRange,ForkedLightClientOptimisticUpdate,ForkedLightClientFinalityUpdate,HistoricalSummariesProof,HistoricalSummariesWithProof,ForkedHistoricalSummariesWithProof

type LightClientUpdateKey struct {
	StartPeriod uint64
	Count       uint64
}

type LightClientBootstrapKey struct {
	BlockHash []byte `ssz-size:"32"`
}

type LightClientFinalityUpdateKey struct {
	FinalizedSlot uint64
}

type LightClientOptimisticUpdateKey struct {
	OptimisticSlot uint64
}

type HistoricalSummariesWithProofKey struct {
	Epoch uint64
}

func (v HistoricalSummariesWithProofKey) ByteLength() uint64 {
	return 8
}

func (v HistoricalSummariesWithProofKey) FixedLength() uint64 {
	return 8
}

func (v HistoricalSummariesWithProofKey) Serialize(w *codec.EncodingWriter) error {
	return w.WriteUint64(v.Epoch)
}

func (v *HistoricalSummariesWithProofKey) Deserialize(r *codec.DecodingReader) error {
	d, err := r.ReadUint64()
	if err != nil {
		return err
	}
	v.Epoch = d
	return nil
}

func (v HistoricalSummariesWithProofKey) HashTreeRoot(h tree.HashFn) common.Root {
	newRoot := common.Root{}
	binary.LittleEndian.PutUint64(newRoot[:], v.Epoch)
	return newRoot
}

type ForkedLightClientBootstrap struct {
	ForkDigest common.ForkDigest
	Bootstrap  common.SpecObj
}

func (flcb *ForkedLightClientBootstrap) Deserialize(spec *common.Spec, dr *codec.DecodingReader) error {
	_, err := dr.Read(flcb.ForkDigest[:])
	if err != nil {
		return err
	}

	switch flcb.ForkDigest {
	case Bellatrix:
		flcb.Bootstrap = &altair.LightClientBootstrap{}
	case Capella:
		flcb.Bootstrap = &capella.LightClientBootstrap{}
	case Deneb:
		flcb.Bootstrap = &deneb.LightClientBootstrap{}
	default:
		return errors.New("unknown fork digest")
	}

	err = flcb.Bootstrap.Deserialize(spec, dr)
	if err != nil {
		return err
	}

	return nil
}

func (flcb *ForkedLightClientBootstrap) Serialize(spec *common.Spec, w *codec.EncodingWriter) error {
	if err := w.Write(flcb.ForkDigest[:]); err != nil {
		return err
	}
	return flcb.Bootstrap.Serialize(spec, w)
}

func (flcb *ForkedLightClientBootstrap) FixedLength(_ *common.Spec) uint64 {
	return 0
}

func (flcb *ForkedLightClientBootstrap) ByteLength(spec *common.Spec) uint64 {
	return 4 + flcb.Bootstrap.ByteLength(spec)
}

func (flcb *ForkedLightClientBootstrap) HashTreeRoot(spec *common.Spec, h tree.HashFn) common.Root {
	return h.HashTreeRoot(flcb.ForkDigest, spec.Wrap(flcb.Bootstrap))
}

type ForkedLightClientUpdate struct {
	ForkDigest        common.ForkDigest
	LightClientUpdate common.SpecObj
}

func (flcu *ForkedLightClientUpdate) Deserialize(spec *common.Spec, dr *codec.DecodingReader) error {
	_, err := dr.Read(flcu.ForkDigest[:])
	if err != nil {
		return err
	}

	switch flcu.ForkDigest {
	case Bellatrix:
		flcu.LightClientUpdate = &altair.LightClientUpdate{}
	case Capella:
		flcu.LightClientUpdate = &capella.LightClientUpdate{}
	case Deneb:
		flcu.LightClientUpdate = &deneb.LightClientUpdate{}
	default:
		return errors.New("unknown fork digest")
	}

	err = flcu.LightClientUpdate.Deserialize(spec, dr)
	if err != nil {
		return err
	}

	return nil
}

func (flcu *ForkedLightClientUpdate) Serialize(spec *common.Spec, w *codec.EncodingWriter) error {
	if err := w.Write(flcu.ForkDigest[:]); err != nil {
		return err
	}
	return flcu.LightClientUpdate.Serialize(spec, w)
}

func (flcu *ForkedLightClientUpdate) FixedLength(_ *common.Spec) uint64 {
	return 0
}

func (flcu *ForkedLightClientUpdate) ByteLength(spec *common.Spec) uint64 {
	return 4 + flcu.LightClientUpdate.ByteLength(spec)
}

func (flcu *ForkedLightClientUpdate) HashTreeRoot(spec *common.Spec, h tree.HashFn) common.Root {
	return h.HashTreeRoot(flcu.ForkDigest, spec.Wrap(flcu.LightClientUpdate))
}

type LightClientUpdateRange []ForkedLightClientUpdate

func (r *LightClientUpdateRange) Deserialize(spec *common.Spec, dr *codec.DecodingReader) error {
	return dr.List(func() codec.Deserializable {
		i := len(*r)
		*r = append(*r, ForkedLightClientUpdate{})
		return spec.Wrap(&((*r)[i]))
	}, 0, 128)
}

func (r LightClientUpdateRange) Serialize(spec *common.Spec, w *codec.EncodingWriter) error {
	return w.List(func(i uint64) codec.Serializable {
		return spec.Wrap(&r[i])
	}, 0, uint64(len(r)))
}

func (r LightClientUpdateRange) ByteLength(spec *common.Spec) (out uint64) {
	for _, v := range r {
		out += v.ByteLength(spec) + codec.OFFSET_SIZE
	}
	return
}

func (r *LightClientUpdateRange) FixedLength(_ *common.Spec) uint64 {
	return 0
}

func (r LightClientUpdateRange) HashTreeRoot(spec *common.Spec, hFn tree.HashFn) common.Root {
	length := uint64(len(r))
	return hFn.ComplexListHTR(func(i uint64) tree.HTR {
		if i < length {
			return spec.Wrap(&r[i])
		}
		return nil
	}, length, 128)
}

type ForkedLightClientOptimisticUpdate struct {
	ForkDigest                  common.ForkDigest
	LightClientOptimisticUpdate common.SpecObj
}

func (flcou *ForkedLightClientOptimisticUpdate) Deserialize(spec *common.Spec, dr *codec.DecodingReader) error {
	_, err := dr.Read(flcou.ForkDigest[:])
	if err != nil {
		return err
	}

	switch flcou.ForkDigest {
	case Bellatrix:
		flcou.LightClientOptimisticUpdate = &altair.LightClientOptimisticUpdate{}
	case Capella:
		flcou.LightClientOptimisticUpdate = &capella.LightClientOptimisticUpdate{}
	case Deneb:
		flcou.LightClientOptimisticUpdate = &deneb.LightClientOptimisticUpdate{}
	default:
		return errors.New("unknown fork digest")
	}

	err = flcou.LightClientOptimisticUpdate.Deserialize(spec, dr)
	if err != nil {
		return err
	}

	return nil
}

func (flcou *ForkedLightClientOptimisticUpdate) Serialize(spec *common.Spec, w *codec.EncodingWriter) error {
	if err := w.Write(flcou.ForkDigest[:]); err != nil {
		return err
	}
	return flcou.LightClientOptimisticUpdate.Serialize(spec, w)
}

func (flcou *ForkedLightClientOptimisticUpdate) FixedLength(_ *common.Spec) uint64 {
	return 0
}

func (flcou *ForkedLightClientOptimisticUpdate) ByteLength(spec *common.Spec) uint64 {
	return 4 + flcou.LightClientOptimisticUpdate.ByteLength(spec)
}

func (flcou *ForkedLightClientOptimisticUpdate) HashTreeRoot(spec *common.Spec, h tree.HashFn) common.Root {
	return h.HashTreeRoot(flcou.ForkDigest, spec.Wrap(flcou.LightClientOptimisticUpdate))
}

func (flcou *ForkedLightClientOptimisticUpdate) GetSignatureSlot() uint64 {
	switch flcou.ForkDigest {
	case Bellatrix:
		return uint64(flcou.LightClientOptimisticUpdate.(*altair.LightClientOptimisticUpdate).SignatureSlot)
	case Capella:
		return uint64(flcou.LightClientOptimisticUpdate.(*capella.LightClientOptimisticUpdate).SignatureSlot)
	case Deneb:
		return uint64(flcou.LightClientOptimisticUpdate.(*deneb.LightClientOptimisticUpdate).SignatureSlot)
	}
	return 0
}

type ForkedLightClientFinalityUpdate struct {
	ForkDigest                common.ForkDigest
	LightClientFinalityUpdate common.SpecObj
}

func (flcfu *ForkedLightClientFinalityUpdate) Deserialize(spec *common.Spec, dr *codec.DecodingReader) error {
	_, err := dr.Read(flcfu.ForkDigest[:])
	if err != nil {
		return err
	}

	switch flcfu.ForkDigest {
	case Bellatrix:
		flcfu.LightClientFinalityUpdate = &altair.LightClientFinalityUpdate{}
	case Capella:
		flcfu.LightClientFinalityUpdate = &capella.LightClientFinalityUpdate{}
	case Deneb:
		flcfu.LightClientFinalityUpdate = &deneb.LightClientFinalityUpdate{}
	default:
		return errors.New("unknown fork digest")
	}

	err = flcfu.LightClientFinalityUpdate.Deserialize(spec, dr)
	if err != nil {
		return err
	}

	return nil
}

func (flcfu *ForkedLightClientFinalityUpdate) Serialize(spec *common.Spec, w *codec.EncodingWriter) error {
	if err := w.Write(flcfu.ForkDigest[:]); err != nil {
		return err
	}
	return flcfu.LightClientFinalityUpdate.Serialize(spec, w)
}

func (flcfu *ForkedLightClientFinalityUpdate) FixedLength(_ *common.Spec) uint64 {
	return 0
}

func (flcfu *ForkedLightClientFinalityUpdate) ByteLength(spec *common.Spec) uint64 {
	return 4 + flcfu.LightClientFinalityUpdate.ByteLength(spec)
}

func (flcfu *ForkedLightClientFinalityUpdate) HashTreeRoot(spec *common.Spec, h tree.HashFn) common.Root {
	return h.HashTreeRoot(flcfu.ForkDigest, spec.Wrap(flcfu.LightClientFinalityUpdate))
}

func (flcfu *ForkedLightClientFinalityUpdate) GetBeaconSlot() uint64 {
	switch flcfu.ForkDigest {
	case Bellatrix:
		return uint64(flcfu.LightClientFinalityUpdate.(*altair.LightClientFinalityUpdate).FinalizedHeader.Slot)
	case Capella:
		return uint64(flcfu.LightClientFinalityUpdate.(*capella.LightClientFinalityUpdate).FinalizedHeader.Beacon.Slot)
	case Deneb:
		return uint64(flcfu.LightClientFinalityUpdate.(*deneb.LightClientFinalityUpdate).FinalizedHeader.Beacon.Slot)
	}
	return 0
}

const HistoricalSummariesProofLen = 6

type HistoricalSummariesProof struct {
	Proof [HistoricalSummariesProofLen]common.Bytes32
}

func (hsp *HistoricalSummariesProof) Deserialize(dr *codec.DecodingReader) error {
	roots := hsp.Proof[:]
	return tree.ReadRoots(dr, &roots, HistoricalSummariesProofLen)
}

func (hsp *HistoricalSummariesProof) Serialize(w *codec.EncodingWriter) error {
	return tree.WriteRoots(w, hsp.Proof[:])
}

func (hsp *HistoricalSummariesProof) ByteLength() uint64 {
	return 32 * HistoricalSummariesProofLen
}

func (hsp *HistoricalSummariesProof) FixedLength() uint64 {
	return 32 * HistoricalSummariesProofLen
}

func (hsp *HistoricalSummariesProof) HashTreeRoot(hFn tree.HashFn) common.Root {
	return hFn.ComplexVectorHTR(func(i uint64) tree.HTR {
		if i < HistoricalSummariesProofLen {
			return &hsp.Proof[i]
		}
		return nil
	}, 5)
}

type HistoricalSummariesWithProof struct {
	EPOCH               common.Epoch
	HistoricalSummaries capella.HistoricalSummaries
	Proof               HistoricalSummariesProof
}

func (hswp *HistoricalSummariesWithProof) Deserialize(spec *common.Spec, dr *codec.DecodingReader) error {
	return dr.Container(&hswp.EPOCH, spec.Wrap(&hswp.HistoricalSummaries), &hswp.Proof)
}

func (hswp *HistoricalSummariesWithProof) Serialize(spec *common.Spec, w *codec.EncodingWriter) error {
	return w.Container(hswp.EPOCH, spec.Wrap(&hswp.HistoricalSummaries), &hswp.Proof)
}

func (hswp *HistoricalSummariesWithProof) ByteLength(spec *common.Spec) uint64 {
	return codec.ContainerLength(hswp.EPOCH, spec.Wrap(&hswp.HistoricalSummaries), &hswp.Proof)
}

func (hswp *HistoricalSummariesWithProof) FixedLength(_ *common.Spec) uint64 {
	return 0
}

func (hswp *HistoricalSummariesWithProof) HashTreeRoot(spec *common.Spec, hFn tree.HashFn) common.Root {
	return hFn.HashTreeRoot(hswp.EPOCH, spec.Wrap(&hswp.HistoricalSummaries), &hswp.Proof)
}

type ForkedHistoricalSummariesWithProof struct {
	ForkDigest                   common.ForkDigest
	HistoricalSummariesWithProof HistoricalSummariesWithProof
}

func (fhswp *ForkedHistoricalSummariesWithProof) Deserialize(spec *common.Spec, dr *codec.DecodingReader) error {
	_, err := dr.Read(fhswp.ForkDigest[:])
	if err != nil {
		return err
	}

	err = fhswp.HistoricalSummariesWithProof.Deserialize(spec, dr)
	if err != nil {
		return err
	}

	return nil
}

func (fhswp *ForkedHistoricalSummariesWithProof) Serialize(spec *common.Spec, w *codec.EncodingWriter) error {
	if err := w.Write(fhswp.ForkDigest[:]); err != nil {
		return err
	}
	return fhswp.HistoricalSummariesWithProof.Serialize(spec, w)
}

func (fhswp ForkedHistoricalSummariesWithProof) FixedLength(_ *common.Spec) uint64 {
	return 0
}

func (fhswp ForkedHistoricalSummariesWithProof) ByteLength(spec *common.Spec) uint64 {
	return 4 + fhswp.HistoricalSummariesWithProof.ByteLength(spec)
}

func (fhswp ForkedHistoricalSummariesWithProof) HashTreeRoot(spec *common.Spec, h tree.HashFn) common.Root {
	return h.HashTreeRoot(fhswp.ForkDigest, spec.Wrap(common.SpecObj(&fhswp.HistoricalSummariesWithProof)))
}
