package beacon

import (
	"bytes"
	"testing"

	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/codec"
	"github.com/zen-eth/shisui/validation"
)

var oracle = validation.NewOracle(nil)

func TestValidation(t *testing.T) {
	validator := NewBeaconValidator(oracle, configs.Mainnet)
	lightClientBootstrapValidation(validator)
	lightClientUpdateValidation(validator)
	lightClientFinalityUpdateValidation(validator)
	lightClientOptimisticUpdateValidation(validator)
}

func lightClientBootstrapValidation(validator *BeaconValidator) error {
	bootstrap, err := GetLightClientBootstrap(0)
	if err != nil {
		return err
	}
	contentKey := make([]byte, 33)
	contentKey[0] = byte(LightClientBootstrap)
	var buf bytes.Buffer
	err = bootstrap.Serialize(validator.spec, codec.NewEncodingWriter(&buf))
	if err != nil {
		return err
	}
	return validator.ValidateContent(contentKey, buf.Bytes())
}

func lightClientUpdateValidation(validator *BeaconValidator) error {
	update, err := GetClientUpdate(0)
	if err != nil {
		return err
	}
	key := &LightClientUpdateKey{
		StartPeriod: 0,
		Count:       1,
	}
	updateRange := LightClientUpdateRange([]ForkedLightClientUpdate{update})
	keyData, err := key.MarshalSSZ()
	if err != nil {
		return err
	}
	contentKey := make([]byte, 0)
	contentKey = append(contentKey, byte(LightClientUpdate))
	contentKey = append(contentKey, keyData...)
	var buf bytes.Buffer
	err = updateRange.Serialize(validator.spec, codec.NewEncodingWriter(&buf))
	if err != nil {
		return err
	}
	return validator.ValidateContent(contentKey, buf.Bytes())
}

func lightClientFinalityUpdateValidation(validator *BeaconValidator) error {
	update, err := GetLightClientFinalityUpdate(0)
	if err != nil {
		return err
	}
	key := &LightClientFinalityUpdateKey{
		FinalizedSlot: 10934316269310501102,
	}
	keyData, err := key.MarshalSSZ()
	if err != nil {
		return err
	}
	contentKey := make([]byte, 0)
	contentKey = append(contentKey, byte(LightClientFinalityUpdate))
	contentKey = append(contentKey, keyData...)
	var buf bytes.Buffer
	err = update.Serialize(validator.spec, codec.NewEncodingWriter(&buf))
	if err != nil {
		return err
	}
	return validator.ValidateContent(contentKey, buf.Bytes())
}

func lightClientOptimisticUpdateValidation(validator *BeaconValidator) error {
	update, err := GetLightClientOptimisticUpdate(0)
	if err != nil {
		return err
	}
	key := &LightClientOptimisticUpdateKey{
		OptimisticSlot: 15067541596220156845,
	}
	keyData, err := key.MarshalSSZ()
	if err != nil {
		return err
	}
	contentKey := make([]byte, 0)
	contentKey = append(contentKey, byte(LightClientOptimisticUpdate))
	contentKey = append(contentKey, keyData...)
	var buf bytes.Buffer
	err = update.Serialize(validator.spec, codec.NewEncodingWriter(&buf))
	if err != nil {
		return err
	}
	return validator.ValidateContent(contentKey, buf.Bytes())
}
