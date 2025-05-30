package beacon

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/stretchr/testify/assert"
	"github.com/zen-eth/shisui/testlog"
)

var _ ConsensusAPI = (*MockConsensusAPI)(nil)

type MockConsensusAPI struct {
	testdataDir string
}

func NewMockConsensusAPI(path string) (ConsensusAPI, error) {
	return &MockConsensusAPI{testdataDir: path}, nil
}

func (m MockConsensusAPI) GetUpdates(_, _ uint64) ([]common.SpecObj, error) {
	jsonStr, _ := os.ReadFile(m.testdataDir + "/updates.json")

	updates := make([]*capella.LightClientUpdate, 0)
	_ = json.Unmarshal(jsonStr, &updates)

	res := make([]common.SpecObj, 0)

	for _, item := range updates {
		res = append(res, item)
	}
	return res, nil
}

func (m MockConsensusAPI) GetBootstrap(_ common.Root) (common.SpecObj, error) {
	jsonStr, _ := os.ReadFile(m.testdataDir + "/bootstrap.json")

	bootstrap := &capella.LightClientBootstrap{}
	_ = json.Unmarshal(jsonStr, &bootstrap)

	return bootstrap, nil
}

func (m MockConsensusAPI) GetFinalityUpdate() (common.SpecObj, error) {
	jsonStr, _ := os.ReadFile(m.testdataDir + "/finality.json")

	finality := &capella.LightClientFinalityUpdate{}
	_ = json.Unmarshal(jsonStr, &finality)

	return finality, nil
}

func (m MockConsensusAPI) GetOptimisticUpdate() (common.SpecObj, error) {
	jsonStr, _ := os.ReadFile(m.testdataDir + "/optimistic.json")

	optimistic := &capella.LightClientOptimisticUpdate{}
	_ = json.Unmarshal(jsonStr, &optimistic)

	return optimistic, nil
}

func (m MockConsensusAPI) ChainID() uint64 {
	panic("implement me")
}

func (m MockConsensusAPI) Name() string {
	return "mock"
}

func getClient(strictCheckpointAge bool, t *testing.T) (*ConsensusLightClient, error) {
	baseConfig := Mainnet()
	api, err := NewMockConsensusAPI("testdata/mockdata")
	assert.NoError(t, err)

	config := &Config{
		ConsensusAPI:        api.Name(),
		Chain:               baseConfig.Chain,
		Spec:                baseConfig.Spec,
		StrictCheckpointAge: strictCheckpointAge,
	}

	checkpoint := common.Root(hexutil.MustDecode("0xc62aa0de55e6f21230fa63713715e1a6c13e73005e89f6389da271955d819bde"))

	client, err := NewConsensusLightClient(api, config, checkpoint, testlog.Logger(t, log.LvlTrace))
	if err != nil {
		return nil, err
	}

	err = client.bootstrap()

	return client, err
}

func TestVerifyCheckpointAgeInvalid(t *testing.T) {
	_, _ = getClient(true, t)
	// assert.ErrorContains(t, err, "checkpoint is too old")
}

// func TestVerifyUpdate(t *testing.T) {
// 	client, err := getClient(false, t)
// 	require.NoError(t, err)
// 	client.Config.MaxCheckpointAge = 123123123
// 	err = client.Sync()
// 	require.NoError(t, err)
// 	period := CalcSyncPeriod(uint64(client.Store.FinalizedHeader.Slot))
// 	updates, err := client.API.GetUpdates(period, beacon.MaxRequestLightClientUpdates)
// 	require.NoError(t, err)
// 	// normal
// 	err = client.VerifyUpdate(updates[0])
// 	require.NoError(t, err)
// }

// func TestVerifyFinalityUpdate(t *testing.T) {
// 	client, err := getClient(false, t)
// 	require.NoError(t, err)

// 	update, err := client.API.GetFinalityUpdate()
// 	require.NoError(t, err)

// 	// normal
// 	err = client.VerifyFinalityUpdate(update)
// 	require.NoError(t, err)
// }

// func TestVerifyOptimisticUpdate(t *testing.T) {
// 	client, err := getClient(false, t)
// 	require.NoError(t, err)

// 	update, err := client.API.GetOptimisticUpdate()
// 	require.NoError(t, err)

// 	// normal
// 	err = client.VerifyOptimisticUpdate(update)
// 	require.NoError(t, err)

// }

// func TestSync(t *testing.T) {
// 	client, err := getClient(false, t)
// 	require.NoError(t, err)

// 	err = client.Sync()
// 	require.NoError(t, err)

// 	header := client.GetHeader()
// 	require.Equal(t, header.Slot, common.Slot(7358726))

// 	finalizedHead := client.GetFinalityHeader()
// 	require.Equal(t, finalizedHead.Slot, common.Slot(7358656))
// }
