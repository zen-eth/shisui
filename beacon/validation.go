package beacon

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/util/merkle"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/tree"
	"github.com/zen-eth/shisui/types/beacon"
	"github.com/zen-eth/shisui/validation"
)

var _ validation.Validator = &BeaconValidator{}

type BeaconValidator struct {
	validationOracle validation.Oracle
	spec             *common.Spec
}

func NewBeaconValidator(oracle validation.Oracle, spec *common.Spec) *BeaconValidator {
	return &BeaconValidator{
		validationOracle: oracle,
		spec:             spec,
	}
}

// ValidateContent implements validation.Validator
func (b *BeaconValidator) ValidateContent(contentKey []byte, content []byte) error {
	switch beacon.ContentType(contentKey[0]) {
	case beacon.LightClientUpdate:
		var lightClientUpdateRange LightClientUpdateRange = make([]ForkedLightClientUpdate, 0)
		err := lightClientUpdateRange.Deserialize(b.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		lightClientUpdateKey := &LightClientUpdateKey{}
		err = lightClientUpdateKey.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return err
		}
		if lightClientUpdateKey.Count != uint64(len(lightClientUpdateRange)) {
			return fmt.Errorf("light client updates count does not match the content key count: %d != %d", len(lightClientUpdateRange), lightClientUpdateKey.Count)
		}
		// TODO miss some validation
		return nil
	case beacon.LightClientBootstrap:
		var forkedLightClientBootstrap ForkedLightClientBootstrap
		err := forkedLightClientBootstrap.Deserialize(b.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		currentSlot := b.spec.TimeToSlot(common.Timestamp(time.Now().Unix()), common.Timestamp(GenesisTime))

		genericBootstrap, err := FromBootstrap(forkedLightClientBootstrap.Bootstrap)
		if err != nil {
			return err
		}
		fourMonth := time.Hour * 24 * 30 * 4
		fourMonthInSlots := common.Timestamp(fourMonth.Seconds()) / (b.spec.SECONDS_PER_SLOT)
		fourMonthAgoSlot := currentSlot - common.Slot(fourMonthInSlots)

		if genericBootstrap.Header.Slot < fourMonthAgoSlot {
			return fmt.Errorf("light client bootstrap slot is too old: %d", genericBootstrap.Header.Slot)
		}
		// TODO validate with finalized header
		return nil
	case beacon.LightClientFinalityUpdate:
		lightClientFinalityUpdateKey := &LightClientFinalityUpdateKey{}
		err := lightClientFinalityUpdateKey.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return err
		}
		var forkedLightClientFinalityUpdate ForkedLightClientFinalityUpdate
		err = forkedLightClientFinalityUpdate.Deserialize(b.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		// TODO it should be Electra now
		if forkedLightClientFinalityUpdate.ForkDigest != Deneb {
			return fmt.Errorf("light client finality update is not from the recent fork. Expected deneb, got %v", forkedLightClientFinalityUpdate.ForkDigest)
		}
		finalizedSlot := lightClientFinalityUpdateKey.FinalizedSlot
		genericUpdate, err := FromLightClientFinalityUpdate(forkedLightClientFinalityUpdate.LightClientFinalityUpdate)
		if err != nil {
			return err
		}
		if finalizedSlot != uint64(genericUpdate.FinalizedHeader.Slot) {
			return fmt.Errorf("light client finality update finalized slot does not match the content key finalized slot: %d != %d", genericUpdate.FinalizedHeader.Slot, finalizedSlot)
		}
		// TODO miss some validation
		return nil
	case beacon.LightClientOptimisticUpdate:
		lightClientOptimisticUpdateKey := &LightClientOptimisticUpdateKey{}
		err := lightClientOptimisticUpdateKey.UnmarshalSSZ(contentKey[1:])
		if err != nil {
			return err
		}
		var forkedLightClientOptimisticUpdate ForkedLightClientOptimisticUpdate
		err = forkedLightClientOptimisticUpdate.Deserialize(b.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
		if err != nil {
			return err
		}
		// TODO it should be Electra now
		if forkedLightClientOptimisticUpdate.ForkDigest != Deneb {
			return fmt.Errorf("light client optimistic update is not from the recent fork. Expected deneb, got %v", forkedLightClientOptimisticUpdate.ForkDigest)
		}
		genericUpdate, err := FromLightClientOptimisticUpdate(forkedLightClientOptimisticUpdate.LightClientOptimisticUpdate)
		if err != nil {
			return err
		}
		// Check if key signature slot matches the light client optimistic update signature slot
		if lightClientOptimisticUpdateKey.OptimisticSlot != uint64(genericUpdate.SignatureSlot) {
			return fmt.Errorf("light client optimistic update signature slot does not match the content key signature slot: %d != %d", genericUpdate.SignatureSlot, lightClientOptimisticUpdateKey.OptimisticSlot)
		}
		// TODO miss some validation
		return nil
	case beacon.HistoricalSummaries:
		forkedHistoricalSummariesWithProof, err := b.generalSummariesValidation(contentKey, content)
		if err != nil {
			return err
		}
		latestFinalizedRoot, err := b.validationOracle.GetFinalizedStateRoot()
		if err != nil {
			return err
		}
		valid := b.stateSummariesValidation(*forkedHistoricalSummariesWithProof, common.Root(latestFinalizedRoot))
		if !valid {
			return errors.New("merkle proof validation failed for HistoricalSummariesProof")
		}
		return nil
	default:
		return fmt.Errorf("unknown content type %v", contentKey[0])
	}
}

func (b *BeaconValidator) generalSummariesValidation(contentKey, content []byte) (*ForkedHistoricalSummariesWithProof, error) {
	key := &HistoricalSummariesWithProofKey{}
	err := key.Deserialize(codec.NewDecodingReader(bytes.NewReader(contentKey[1:]), uint64(len(contentKey[1:]))))
	if err != nil {
		return nil, err
	}
	forkedHistoricalSummariesWithProof := &ForkedHistoricalSummariesWithProof{}
	err = forkedHistoricalSummariesWithProof.Deserialize(b.spec, codec.NewDecodingReader(bytes.NewReader(content), uint64(len(content))))
	if err != nil {
		return nil, err
	}
	if forkedHistoricalSummariesWithProof.HistoricalSummariesWithProof.EPOCH != common.Epoch(key.Epoch) {
		return nil, fmt.Errorf("historical summaries with proof epoch does not match the content key epoch: %d != %d", forkedHistoricalSummariesWithProof.HistoricalSummariesWithProof.EPOCH, key.Epoch)
	}
	return forkedHistoricalSummariesWithProof, nil
}

func (b *BeaconValidator) stateSummariesValidation(f ForkedHistoricalSummariesWithProof, latestFinalizedRoot common.Root) bool {
	proof := f.HistoricalSummariesWithProof.Proof
	summariesRoot := f.HistoricalSummariesWithProof.HistoricalSummaries.HashTreeRoot(b.spec, tree.GetHashFn())

	gIndex := 59
	return merkle.VerifyMerkleBranch(summariesRoot, proof.Proof[:], 5, uint64(gIndex), latestFinalizedRoot)
}
