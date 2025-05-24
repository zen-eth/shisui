package portalwire

import (
	"github.com/stretchr/testify/require"
	"sync"
	"sync/atomic"
	"testing"
)

func testUtpControllerPermitAcquisition(t *testing.T, getPermit func() Permit, releasePermit func(Permit)) {
	firstPermit := getPermit()
	require.NotNil(t, firstPermit)

	noPermit := getPermit()
	require.Equal(t, PermitReject, noPermit)
	releasePermit(noPermit)
	stillLimited := getPermit()
	require.Equal(t, PermitReject, stillLimited)

	// after release permit, should be able to get permit again
	releasePermit(firstPermit)
	secondPermit := getPermit()
	require.NotNil(t, secondPermit)

	// should not be able to get permit
	noPermit = getPermit()
	require.Equal(t, PermitReject, noPermit)
}

func TestUtpController_GetPermit(t *testing.T) {
	utpCtrl := newUtpController(1)
	testUtpControllerPermitAcquisition(t, utpCtrl.GetInboundPermit, utpCtrl.Release)
	testUtpControllerPermitAcquisition(t, utpCtrl.GetOutboundPermit, utpCtrl.Release)
}

func testUtpControllerConcurrencyGetPermitAcquisition(t *testing.T, getPermit func() Permit) {
	var permitCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			permit := getPermit()
			if permit == PermitInbound || permit == PermitOutbound {
				permitCount.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(5), permitCount.Load())
}

func TestUtpControllerConcurrencyGetPermit(t *testing.T) {
	utpCtrl := newUtpController(5)
	testUtpControllerConcurrencyGetPermitAcquisition(t, utpCtrl.GetOutboundPermit)
	testUtpControllerConcurrencyGetPermitAcquisition(t, utpCtrl.GetInboundPermit)
}
