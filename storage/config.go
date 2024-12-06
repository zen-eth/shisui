package storage

import (
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/protolambda/zrnt/eth2/beacon/common"
)

type PortalStorageConfig struct {
	StorageCapacityMB uint64
	NodeId            enode.ID
	Spec              *common.Spec
	NetworkName       string
}
