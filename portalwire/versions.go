package portalwire

import (
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

type protocolVersions []uint8

func (pv protocolVersions) ENRKey() string { return "pv" }

var Versions protocolVersions = protocolVersions{0, 1} //protocol network versions defined here

const expiryMinutes = 5 // expiry time in minutes

// maxCompatibleVersionSize ideally should have the buckets plus the replacement Buckets size
const maxCompatibleVersionSize = nBuckets * (bucketSize + maxReplacements)

type activeVersions struct {
	currentVersions protocolVersions          //versions implemented currently
	highestVersion  map[*enode.Node]uint8     //map nodes highest compatible version
	expireTime      map[*enode.Node]time.Time //map nodes with expiry time
	count           int                       //count nodes stored
	log             log.Logger
}

func newActiveVersions(log log.Logger) *activeVersions {
	return &activeVersions{
		currentVersions: Versions,
		highestVersion:  make(map[*enode.Node]uint8),
		expireTime:      make(map[*enode.Node]time.Time),
		count:           0,
		log:             log,
	}
}

func (av *activeVersions) getHighestVersion(node *enode.Node) uint8 {
	//if the node is not mapped, or its mapping is expired update highest version
	_, mapped := av.highestVersion[node]
	if !mapped || time.Now().After(av.expireTime[node]) {
		av.updateHighestVersion(node)
	}

	return av.highestVersion[node]
}

func (av *activeVersions) updateHighestVersion(node *enode.Node) {
	//check mapping count to prevent memory leak
	_, mapped := av.highestVersion[node]
	if av.count == maxCompatibleVersionSize && !mapped {
		av.log.Debug("highest compatible version mapping full, can not update", "node", node.String())
		return
	} else if !mapped {
		av.count++
	}

	versions := &protocolVersions{}
	av.expireTime[node] = time.Now().Add(time.Minute * time.Duration(expiryMinutes))

	err := node.Load(versions)
	// if any error, assumes version default 0
	if err != nil {
		av.highestVersion[node] = 0
		av.log.Debug("could not determine highest compatible version, will use 0", "node", node.String(), "err", err)
		return
	}

	av.highestVersion[node], err = findBiggestSameNumber(av.currentVersions, *versions)
	if err != nil {
		av.log.Debug("error on highest version number", "node", node.String(), "err", err)
	}
}

func (av *activeVersions) deleteHighestVersion(node *enode.Node) {
	_, mapped := av.highestVersion[node]
	if mapped {
		av.count--
		delete(av.highestVersion, node)
		delete(av.expireTime, node)
	}
}

// findTheBiggestSameNumber finds the largest value that exists in both slices.
// Returns the largest common value, or an error if there are no common values.
func findBiggestSameNumber(a []uint8, b []uint8) (uint8, error) {
	if len(a) == 0 || len(b) == 0 {
		return 0, errors.New("empty slice provided")
	}

	// Create a map to track values in the first slice
	valuesInA := make(map[uint8]bool)
	for _, val := range a {
		valuesInA[val] = true
	}

	// Find common values and track the maximum
	var maxCommon uint8
	foundCommon := false

	for _, val := range b {
		if valuesInA[val] {
			foundCommon = true
			if val > maxCommon {
				maxCommon = val
			}
		}
	}

	if !foundCommon {
		return 0, errors.New("no common values found")
	}

	return maxCommon, nil
}
