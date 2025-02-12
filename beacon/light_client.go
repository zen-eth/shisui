package beacon

import (
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/protolambda/zrnt/eth2/beacon/altair"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/zrnt/eth2/util/merkle"

	"github.com/ethereum/go-ethereum/common/hexutil"
	blsu "github.com/protolambda/bls12-381-util"
	"github.com/protolambda/ztyp/tree"
	"github.com/protolambda/ztyp/view"
)

var (
	ErrInsufficientParticipation     = errors.New("insufficient participation")
	ErrInvalidTimestamp              = errors.New("invalid timestamp")
	ErrInvalidPeriod                 = errors.New("invalid sync committee period")
	ErrNotRelevant                   = errors.New("update not relevant")
	ErrInvalidFinalityProof          = errors.New("invalid finality proof")
	ErrInvalidNextSyncCommitteeProof = errors.New("invalid next sync committee proof")
	ErrInvalidSignature              = errors.New("invalid sync committee signature")
)

type LightClientStore struct {
	FinalizedHeader               *common.BeaconBlockHeader
	CurrentSyncCommittee          *common.SyncCommittee
	NextSyncCommittee             *common.SyncCommittee
	OptimisticHeader              *common.BeaconBlockHeader
	PreviousMaxActiveParticipants view.Uint64View
	CurrentMaxActiveParticipants  view.Uint64View
}

type ConsensusLightClient struct {
	Store             LightClientStore
	API               ConsensusAPI
	InitialCheckpoint common.Root
	LastCheckpoint    common.Root
	Config            *Config
	Logger            log.Logger
}

type GenericUpdate struct {
	AttestedHeader          *common.BeaconBlockHeader
	SyncAggregate           *altair.SyncAggregate
	SignatureSlot           common.Slot
	NextSyncCommittee       *common.SyncCommittee
	NextSyncCommitteeBranch *altair.SyncCommitteeProofBranch
	FinalizedHeader         *common.BeaconBlockHeader
	FinalityBranch          *altair.FinalizedRootProofBranch
}

type GenericBootstrap struct {
	Header                     *common.BeaconBlockHeader
	CurrentSyncCommittee       common.SyncCommittee
	CurrentSyncCommitteeBranch altair.SyncCommitteeProofBranch
}

func FromBootstrap(commonBootstrap common.SpecObj) (*GenericBootstrap, error) {
	switch bootstrap := commonBootstrap.(type) {
	case *deneb.LightClientBootstrap:
		return &GenericBootstrap{
			Header:                     &bootstrap.Header.Beacon,
			CurrentSyncCommittee:       bootstrap.CurrentSyncCommittee,
			CurrentSyncCommitteeBranch: bootstrap.CurrentSyncCommitteeBranch,
		}, nil
	case *capella.LightClientBootstrap:
		return &GenericBootstrap{
			Header:                     &bootstrap.Header.Beacon,
			CurrentSyncCommittee:       bootstrap.CurrentSyncCommittee,
			CurrentSyncCommitteeBranch: bootstrap.CurrentSyncCommitteeBranch,
		}, nil
	case *altair.LightClientBootstrap:
		return &GenericBootstrap{
			Header:                     &bootstrap.Header.Beacon,
			CurrentSyncCommittee:       bootstrap.CurrentSyncCommittee,
			CurrentSyncCommitteeBranch: bootstrap.CurrentSyncCommitteeBranch,
		}, nil
	}
	return nil, errors.New("unknown bootstrap type")
}

func NewConsensusLightClient(api ConsensusAPI, config *Config, checkpointBlockRoot common.Root, logger log.Logger) (*ConsensusLightClient, error) {
	client := &ConsensusLightClient{
		API:               api,
		Config:            config,
		Logger:            logger,
		InitialCheckpoint: checkpointBlockRoot,
	}

	// err := client.bootstrap()
	// if err != nil {
	// 	return nil, err
	// }

	return client, nil
}

func (c *ConsensusLightClient) Start() error {
	err := c.Sync()
	if err != nil {
		return err
	}
	go func() {
		for {
			err := c.Advance()
			if err != nil {
				c.Logger.Warn("error advancing light client", "err", err)
			}

			duration := c.DurationUntilNextUpdate()
			time.Sleep(duration)
		}
	}()
	return nil
}

func (c *ConsensusLightClient) GetHeader() *common.BeaconBlockHeader {
	return c.Store.OptimisticHeader
}

func (c *ConsensusLightClient) GetFinalityHeader() *common.BeaconBlockHeader {
	return c.Store.FinalizedHeader
}

func (c *ConsensusLightClient) Sync() error {
	err := c.bootstrap()
	if err != nil {
		return err
	}

	bootstrapPeriod := CalcSyncPeriod(uint64(c.Store.FinalizedHeader.Slot))

	updates := make([]common.SpecObj, 0)

	if c.API.Name() == "portal" {
		currentPeriod := CalcSyncPeriod(uint64(c.expectedCurrentSlot()))
		for i := bootstrapPeriod; i < currentPeriod; i++ {
			update, err := c.API.GetUpdates(i, 1)
			if err != nil {
				return err
			}
			updates = append(updates, update...)
		}
	} else {
		updates, err = c.API.GetUpdates(bootstrapPeriod, MaxRequestLightClientUpdates)
		if err != nil {
			return err
		}
	}

	for _, update := range updates {
		err = c.VerifyUpdate(update)
		if err != nil {
			return err
		}
		err = c.ApplyUpdate(update)
		if err != nil {
			return err
		}
	}

	finalityUpdate, err := c.API.GetFinalityUpdate()
	if err != nil {
		return err
	}
	err = c.VerifyFinalityUpdate(finalityUpdate)
	if err != nil {
		return err
	}
	err = c.ApplyFinalityUpdate(finalityUpdate)
	if err != nil {
		return err
	}

	optimisticUpdate, err := c.API.GetOptimisticUpdate()
	if err != nil {
		return err
	}
	err = c.VerifyOptimisticUpdate(optimisticUpdate)
	if err != nil {
		return err
	}
	err = c.ApplyOptimisticUpdate(optimisticUpdate)
	if err != nil {
		return err
	}

	c.Logger.Info("Light client in sync with ", "checkpoint", hexutil.Encode(c.InitialCheckpoint[:]))
	return nil
}

func (c *ConsensusLightClient) Advance() error {
	finalityUpdate, err := c.API.GetFinalityUpdate()
	if err != nil {
		return err
	}
	err = c.VerifyFinalityUpdate(finalityUpdate)
	if err != nil {
		return err
	}
	err = c.ApplyFinalityUpdate(finalityUpdate)
	if err != nil {
		return err
	}

	optimisticUpdate, err := c.API.GetOptimisticUpdate()
	if err != nil {
		return err
	}
	err = c.VerifyOptimisticUpdate(optimisticUpdate)
	if err != nil {
		return err
	}
	err = c.ApplyOptimisticUpdate(optimisticUpdate)
	if err != nil {
		return err
	}

	if c.Store.NextSyncCommittee == nil {
		c.Logger.Debug("checking for sync committee update")
		currentPeriod := CalcSyncPeriod(uint64(c.Store.FinalizedHeader.Slot))
		updates, err := c.API.GetUpdates(currentPeriod, 1)
		if err != nil {
			return err
		}
		if len(updates) == 1 {
			update := updates[0]
			err = c.VerifyUpdate(update)
			if err != nil {
				return err
			}
			c.Logger.Info("updating sync committee")
			err := c.ApplyUpdate(update)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *ConsensusLightClient) bootstrap() error {
	forkedBootstrap, err := c.API.GetBootstrap(c.InitialCheckpoint)
	if err != nil {
		return err
	}
	bootstrap, err := FromBootstrap(forkedBootstrap)
	if err != nil {
		return err
	}
	isValid := c.isValidCheckpoint(bootstrap.Header.Slot)
	if !isValid {
		if c.Config.StrictCheckpointAge {
			return errors.New("checkpoint is too old")
		} else {
			c.Logger.Warn("checkpoint is too old")
		}
	}

	committeeValid := c.isCurrentCommitteeProofValid(*bootstrap.Header, bootstrap.CurrentSyncCommittee, bootstrap.CurrentSyncCommitteeBranch)

	headerHash := bootstrap.Header.HashTreeRoot(tree.GetHashFn()).String()
	expectedHash := c.InitialCheckpoint.String()

	headerValid := headerHash == expectedHash

	if !headerValid {
		return fmt.Errorf("header hash %s does not match expected hash %s", headerHash, expectedHash)
	}

	if !committeeValid {
		return errors.New("committee proof is invalid")
	}

	c.Store = LightClientStore{
		FinalizedHeader:               bootstrap.Header,
		CurrentSyncCommittee:          &bootstrap.CurrentSyncCommittee,
		OptimisticHeader:              bootstrap.Header,
		PreviousMaxActiveParticipants: view.Uint64View(0),
		CurrentMaxActiveParticipants:  view.Uint64View(0),
	}

	return nil
}

func (c *ConsensusLightClient) isValidCheckpoint(blockHashSlot common.Slot) bool {
	currentSlot := c.expectedCurrentSlot()
	currentSlotTimestamp, err := c.slotTimestamp(currentSlot)
	if err != nil {
		return false
	}
	blockHashSlotTimestamp, err := c.slotTimestamp(blockHashSlot)
	if err != nil {
		return false
	}

	slotAge := currentSlotTimestamp - blockHashSlotTimestamp

	return uint64(slotAge) < c.Config.MaxCheckpointAge
}

func (c *ConsensusLightClient) VerifyGenericUpdate(update *GenericUpdate) error {
	bits := c.getBits(update.SyncAggregate.SyncCommitteeBits)
	if bits == 0 {
		return ErrInsufficientParticipation
	}
	updateFinalizedSlot := common.Slot(0)
	if update.FinalizedHeader != nil {
		updateFinalizedSlot = update.FinalizedHeader.Slot
	}
	validTime := uint64(c.expectedCurrentSlot()) >= uint64(update.SignatureSlot) && update.SignatureSlot > update.AttestedHeader.Slot && update.AttestedHeader.Slot >= updateFinalizedSlot
	if !validTime {
		return ErrInvalidTimestamp
	}

	storePeriod := CalcSyncPeriod(uint64(c.Store.FinalizedHeader.Slot))
	updateSigPeriod := CalcSyncPeriod(uint64(update.SignatureSlot))
	validPeriod := false
	if c.Store.NextSyncCommittee != nil {
		validPeriod = updateSigPeriod == storePeriod || updateSigPeriod == storePeriod+1
	} else {
		validPeriod = updateSigPeriod == storePeriod
	}
	if !validPeriod {
		return ErrInvalidPeriod
	}

	updateAttestedPeriod := CalcSyncPeriod(uint64(update.AttestedHeader.Slot))
	updateHasNextCommittee := c.Store.NextSyncCommittee == nil && update.NextSyncCommittee != nil && updateAttestedPeriod == storePeriod

	if update.AttestedHeader.Slot <= c.Store.FinalizedHeader.Slot && !updateHasNextCommittee {
		return ErrNotRelevant
	}
	if update.FinalizedHeader != nil && update.FinalityBranch != nil {
		isValid := IsFinalityProofValid(*update.AttestedHeader, *update.FinalizedHeader, *update.FinalityBranch)
		if !isValid {
			return ErrInvalidFinalityProof
		}
	}
	if update.NextSyncCommittee != nil && update.NextSyncCommitteeBranch != nil {
		isValid := IsNextCommitteeProofValid(*update.AttestedHeader, *update.NextSyncCommittee, *update.NextSyncCommitteeBranch)
		if !isValid {
			return ErrInvalidNextSyncCommitteeProof
		}
	}
	var syncCommittee *common.SyncCommittee

	if updateSigPeriod == storePeriod {
		syncCommittee = c.Store.CurrentSyncCommittee
	} else {
		syncCommittee = c.Store.NextSyncCommittee
	}

	pks := c.getParticipatingKeys(*syncCommittee, update.SyncAggregate.SyncCommitteeBits)

	isValidSig, err := c.VerifySyncCommitteeSignature(pks, *update.AttestedHeader, update.SyncAggregate.SyncCommitteeSignature, update.SignatureSlot)
	if err != nil {
		return err
	}
	if !isValidSig {
		return ErrInvalidSignature
	}
	return nil
}

func (c *ConsensusLightClient) VerifyUpdate(update common.SpecObj) error {
	genericUpdate, err := FromLightClientUpdate(update)
	if err != nil {
		return err
	}
	return c.VerifyGenericUpdate(genericUpdate)
}

func (c *ConsensusLightClient) VerifyFinalityUpdate(update common.SpecObj) error {
	genericUpdate, err := FromLightClientFinalityUpdate(update)
	if err != nil {
		return err
	}
	return c.VerifyGenericUpdate(genericUpdate)
}

func (c *ConsensusLightClient) VerifyOptimisticUpdate(update common.SpecObj) error {
	genericUpdate, err := FromLightClientOptimisticUpdate(update)
	if err != nil {
		return err
	}
	return c.VerifyGenericUpdate(genericUpdate)
}

func (c *ConsensusLightClient) ApplyGenericUpdate(update *GenericUpdate) {
	commiteeBits := c.getBits(update.SyncAggregate.SyncCommitteeBits)

	if c.Store.CurrentMaxActiveParticipants < view.Uint64View(commiteeBits) {
		c.Store.CurrentMaxActiveParticipants = view.Uint64View(commiteeBits)
	}

	shouldUpdateOptimistic := commiteeBits > c.safetyThreshold() && update.AttestedHeader.Slot > c.Store.OptimisticHeader.Slot

	if shouldUpdateOptimistic {
		c.Store.OptimisticHeader = update.AttestedHeader
		c.logFinalityUpdate(update)
	}

	updateAttestedPeriod := CalcSyncPeriod(uint64(update.AttestedHeader.Slot))

	updateFinalizedSlot := common.Slot(0)
	if update.FinalizedHeader != nil {
		updateFinalizedSlot = update.FinalizedHeader.Slot
	}

	updateFinalizedPeriod := CalcSyncPeriod(uint64(updateFinalizedSlot))

	updateHasFinalizedNextCommittee := c.Store.NextSyncCommittee == nil &&
		c.hasSyncUpdate(update) &&
		c.hasFinalityUpdate(update) &&
		updateFinalizedPeriod == updateAttestedPeriod

	hasMajority := commiteeBits*3 >= 512*2
	updateIsNewer := updateFinalizedSlot > c.Store.FinalizedHeader.Slot
	goodUpdate := updateIsNewer || updateHasFinalizedNextCommittee

	shouldApplyUpdate := hasMajority && goodUpdate

	if shouldApplyUpdate {
		storePeriod := CalcSyncPeriod(uint64(c.Store.FinalizedHeader.Slot))

		if c.Store.NextSyncCommittee == nil {
			c.Store.NextSyncCommittee = update.NextSyncCommittee
		} else if updateFinalizedPeriod == storePeriod+1 {
			c.Logger.Info("sync committee updated")
			c.Store.CurrentSyncCommittee = c.Store.NextSyncCommittee
			c.Store.NextSyncCommittee = update.NextSyncCommittee
			c.Store.PreviousMaxActiveParticipants = c.Store.CurrentMaxActiveParticipants
			c.Store.CurrentMaxActiveParticipants = 0
		}

		if updateFinalizedSlot > c.Store.FinalizedHeader.Slot {
			c.Store.FinalizedHeader = update.FinalizedHeader
			c.logFinalityUpdate(update)

			if c.Store.FinalizedHeader.Slot%32 == 0 {
				checkpoint := c.Store.FinalizedHeader.HashTreeRoot(tree.GetHashFn())
				c.LastCheckpoint = checkpoint
			}

			if c.Store.FinalizedHeader.Slot > c.Store.OptimisticHeader.Slot {
				c.Store.OptimisticHeader = c.Store.FinalizedHeader
			}
		}
	}
}

func (c *ConsensusLightClient) ApplyUpdate(update common.SpecObj) error {
	genericUpdate, err := FromLightClientUpdate(update)
	if err != nil {
		return err
	}
	c.ApplyGenericUpdate(genericUpdate)
	return nil
}

func (c *ConsensusLightClient) ApplyFinalityUpdate(update common.SpecObj) error {
	genericUpdate, err := FromLightClientFinalityUpdate(update)
	if err != nil {
		return err
	}
	c.ApplyGenericUpdate(genericUpdate)
	return nil
}

func (c *ConsensusLightClient) ApplyOptimisticUpdate(update common.SpecObj) error {
	genericUpdate, err := FromLightClientOptimisticUpdate(update)
	if err != nil {
		return err
	}
	c.ApplyGenericUpdate(genericUpdate)
	return nil
}

func (c *ConsensusLightClient) VerifySyncCommitteeSignature(pks []common.BLSPubkey, attestedHeader common.BeaconBlockHeader, signature common.BLSSignature, signatureSlot common.Slot) (bool, error) {
	headerRoot := attestedHeader.HashTreeRoot(tree.GetHashFn())
	signingRoot := c.ComputeCommitteeSignRoot(headerRoot, signatureSlot)
	blsuPubKeys := make([]*blsu.Pubkey, 0, len(pks))
	for _, p := range pks {
		blsuPubKey, err := p.Pubkey()
		if err != nil {
			return false, err
		}
		blsuPubKeys = append(blsuPubKeys, blsuPubKey)
	}
	blsuSig, err := signature.Signature()
	if err != nil {
		return false, err
	}
	return blsu.FastAggregateVerify(blsuPubKeys, signingRoot[:], blsuSig), nil
}

func (c *ConsensusLightClient) ComputeCommitteeSignRoot(headerRoot tree.Root, slot common.Slot) common.Root {
	genesisRoot := c.Config.Chain.GenesisRoot
	domainType := hexutil.MustDecode("0x07000000")
	forkVersion := c.Config.Spec.ForkVersion(slot)
	domain := common.ComputeDomain(common.BLSDomainType(domainType), forkVersion, genesisRoot)
	return ComputeSigningRoot(headerRoot, domain)
}

func (c *ConsensusLightClient) expectedCurrentSlot() common.Slot {
	return c.Config.Spec.TimeToSlot(common.Timestamp(time.Now().Unix()), common.Timestamp(c.Config.Chain.GenesisTime))
}

func (c *ConsensusLightClient) slotTimestamp(slot common.Slot) (common.Timestamp, error) {
	atSlot, err := c.Config.Spec.TimeAtSlot(slot, common.Timestamp(c.Config.Chain.GenesisTime))
	if err != nil {
		return 0, err
	}

	return atSlot, nil
}

func (c *ConsensusLightClient) isCurrentCommitteeProofValid(attestedHeader common.BeaconBlockHeader, currentCommittee common.SyncCommittee, currentCommitteeBranch altair.SyncCommitteeProofBranch) bool {
	return merkle.VerifyMerkleBranch(currentCommittee.HashTreeRoot(c.Config.Spec, tree.GetHashFn()), currentCommitteeBranch[:], 5, 22, attestedHeader.StateRoot)
}

func (c *ConsensusLightClient) safetyThreshold() uint64 {
	if c.Store.CurrentMaxActiveParticipants > c.Store.PreviousMaxActiveParticipants {
		return uint64(c.Store.CurrentMaxActiveParticipants) / 2
	} else {
		return uint64(c.Store.PreviousMaxActiveParticipants) / 2
	}
}

func (c *ConsensusLightClient) hasSyncUpdate(update *GenericUpdate) bool {
	return update.NextSyncCommittee != nil && update.NextSyncCommitteeBranch != nil
}

func (c *ConsensusLightClient) hasFinalityUpdate(update *GenericUpdate) bool {
	return update.FinalizedHeader != nil && update.FinalityBranch != nil
}

func (c *ConsensusLightClient) logFinalityUpdate(update *GenericUpdate) {
	count := c.getBits(update.SyncAggregate.SyncCommitteeBits)
	participation := float32(count) / 512 * 100
	decimals := 0
	if participation == 100.0 {
		decimals = 1
	} else {
		decimals = 2
	}
	slot := c.Store.OptimisticHeader.Slot
	age, err := c.age(slot)
	if err != nil {
		c.Logger.Error("failed to get age", "slot is", slot, "err is", err)
		return
	}
	days := int(age.Hours() / 24)
	hours := int(age.Hours()) % 24
	minutes := int(age.Minutes()) % 60
	secs := int(age.Seconds()) % 60
	ageStr := fmt.Sprintf("%d:%d:%d:%d", days, hours, minutes, secs)
	c.Logger.Info("update header", "slot=", slot, "confidence=", decimals, "age", ageStr)
}

func (c *ConsensusLightClient) age(slot common.Slot) (time.Duration, error) {
	expectTime, err := c.slotTimestamp(slot)
	if err != nil {
		return time.Duration(0), err
	}
	return time.Since(time.Unix(int64(expectTime), 0)), nil
}

func (c *ConsensusLightClient) getBits(sync altair.SyncCommitteeBits) uint64 {
	res := 0
	for i := 0; i < int(c.Config.Spec.SYNC_COMMITTEE_SIZE); i++ {
		if sync.GetBit(uint64(i)) {
			res++
		}
	}
	return uint64(res)
}

func (c *ConsensusLightClient) getParticipatingKeys(committee common.SyncCommittee, syncBits altair.SyncCommitteeBits) []common.BLSPubkey {
	res := make([]common.BLSPubkey, 0)
	for i := 0; i < int(c.Config.Spec.SYNC_COMMITTEE_SIZE); i++ {
		if syncBits.GetBit(uint64(i)) {
			res = append(res, committee.Pubkeys[i])
		}
	}
	return res
}

func (c *ConsensusLightClient) DurationUntilNextUpdate() time.Duration {
	currentSlot := c.expectedCurrentSlot()
	nextSlot := currentSlot + 1
	nextSlotTimestamp, err := c.slotTimestamp(nextSlot)
	if err != nil {
		c.Logger.Warn("failed to get next slot timestamp", "err is", err, "slot is", nextSlot)
		return time.Duration(10)
	}
	now := time.Now().Unix()
	timeToNextSlot := uint64(nextSlotTimestamp) - uint64(now)
	nextUpdate := timeToNextSlot + 8
	return time.Duration(nextUpdate) * time.Second
}

func FromLightClientUpdate(commonUpdate common.SpecObj) (*GenericUpdate, error) {
	switch update := commonUpdate.(type) {
	case *deneb.LightClientUpdate:
		return &GenericUpdate{
			AttestedHeader:          &update.AttestedHeader.Beacon,
			SyncAggregate:           &update.SyncAggregate,
			SignatureSlot:           update.SignatureSlot,
			NextSyncCommittee:       &update.NextSyncCommittee,
			NextSyncCommitteeBranch: &update.NextSyncCommitteeBranch,
			FinalizedHeader:         &update.FinalizedHeader.Beacon,
			FinalityBranch:          &update.FinalityBranch,
		}, nil
	case *capella.LightClientUpdate:
		return &GenericUpdate{
			AttestedHeader:          &update.AttestedHeader.Beacon,
			SyncAggregate:           &update.SyncAggregate,
			SignatureSlot:           update.SignatureSlot,
			NextSyncCommittee:       &update.NextSyncCommittee,
			NextSyncCommitteeBranch: &update.NextSyncCommitteeBranch,
			FinalizedHeader:         &update.FinalizedHeader.Beacon,
			FinalityBranch:          &update.FinalityBranch,
		}, nil
	case *altair.LightClientUpdate:
		return &GenericUpdate{
			AttestedHeader:          &update.AttestedHeader.Beacon,
			SyncAggregate:           &update.SyncAggregate,
			SignatureSlot:           update.SignatureSlot,
			NextSyncCommittee:       &update.NextSyncCommittee,
			NextSyncCommitteeBranch: &update.NextSyncCommitteeBranch,
			FinalizedHeader:         &update.FinalizedHeader.Beacon,
			FinalityBranch:          &update.FinalityBranch,
		}, nil
	}
	return nil, errors.New("unknown update type")
}

func FromLightClientFinalityUpdate(commonFinalityUpdate common.SpecObj) (*GenericUpdate, error) {
	switch update := commonFinalityUpdate.(type) {
	case *deneb.LightClientFinalityUpdate:
		return &GenericUpdate{
			AttestedHeader:  &update.AttestedHeader.Beacon,
			SyncAggregate:   &update.SyncAggregate,
			SignatureSlot:   update.SignatureSlot,
			FinalizedHeader: &update.FinalizedHeader.Beacon,
			FinalityBranch:  &update.FinalityBranch,
		}, nil
	case *capella.LightClientFinalityUpdate:
		return &GenericUpdate{
			AttestedHeader:  &update.AttestedHeader.Beacon,
			SyncAggregate:   &update.SyncAggregate,
			SignatureSlot:   update.SignatureSlot,
			FinalizedHeader: &update.FinalizedHeader.Beacon,
			FinalityBranch:  &update.FinalityBranch,
		}, nil
	case *altair.LightClientFinalityUpdate:
		return &GenericUpdate{
			AttestedHeader:  &update.AttestedHeader.Beacon,
			SyncAggregate:   &update.SyncAggregate,
			SignatureSlot:   update.SignatureSlot,
			FinalizedHeader: &update.FinalizedHeader,
			FinalityBranch:  &update.FinalityBranch,
		}, nil
	}
	return nil, errors.New("unknown finality update type")
}

func FromLightClientOptimisticUpdate(commonOptimisticUpdate common.SpecObj) (*GenericUpdate, error) {
	switch update := commonOptimisticUpdate.(type) {
	case *deneb.LightClientOptimisticUpdate:
		return &GenericUpdate{
			AttestedHeader: &update.AttestedHeader.Beacon,
			SyncAggregate:  &update.SyncAggregate,
			SignatureSlot:  update.SignatureSlot,
		}, nil
	case *capella.LightClientOptimisticUpdate:
		return &GenericUpdate{
			AttestedHeader: &update.AttestedHeader.Beacon,
			SyncAggregate:  &update.SyncAggregate,
			SignatureSlot:  update.SignatureSlot,
		}, nil
	case *altair.LightClientOptimisticUpdate:
		return &GenericUpdate{
			AttestedHeader: &update.AttestedHeader.Beacon,
			SyncAggregate:  &update.SyncAggregate,
			SignatureSlot:  update.SignatureSlot,
		}, nil
	}
	return nil, errors.New("unknown optimistic update type")
}

func ComputeSigningRoot(root common.Root, domain common.BLSDomain) common.Root {
	data := common.SigningData{
		ObjectRoot: root,
		Domain:     domain,
	}
	return data.HashTreeRoot(tree.GetHashFn())
}

func CalcSyncPeriod(slot uint64) uint64 {
	epoch := slot / 32 // 32 slots per epoch
	return epoch / 256 // 256 epochs per sync committee
}

func IsFinalityProofValid(attestedHeader common.BeaconBlockHeader, finalityHeader common.BeaconBlockHeader, finalityBranch altair.FinalizedRootProofBranch) bool {
	leaf := finalityHeader.HashTreeRoot(tree.GetHashFn())
	root := attestedHeader.StateRoot
	return merkle.VerifyMerkleBranch(leaf, finalityBranch[:], 6, 41, root)
}

func IsNextCommitteeProofValid(attestedHeader common.BeaconBlockHeader, nextCommittee common.SyncCommittee, nextCommitteeBranch altair.SyncCommitteeProofBranch) bool {
	leaf := nextCommittee.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	root := attestedHeader.StateRoot
	return merkle.VerifyMerkleBranch(leaf, nextCommitteeBranch[:], 5, 23, root)
}
