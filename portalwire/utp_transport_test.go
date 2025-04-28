package portalwire

import (
	"github.com/stretchr/testify/require"
	"sync"
	"sync/atomic"
	"testing"
)

func testUtpControllerPermitAcquisition(t *testing.T, getPermit func() (Permit, bool)) {
	firstPermit, ok := getPermit()
	require.True(t, ok)
	require.NotNil(t, firstPermit)

	noPermit, ok := getPermit()
	require.False(t, ok)
	require.NotNil(t, noPermit)
	noPermit.Release()
	stillLimited, ok := getPermit()
	require.False(t, ok)
	require.NotNil(t, stillLimited)

	// after release permit, should be able to get permit again
	firstPermit.Release()
	secondPermit, ok := getPermit()
	require.True(t, ok)
	require.NotNil(t, secondPermit)

	// should not be able to get permit
	noPermit, ok = getPermit()
	require.False(t, ok)
	require.NotNil(t, noPermit)
}

func TestUtpController_GetPermit(t *testing.T) {
	utpCtrl := newUtpController(1)
	testUtpControllerPermitAcquisition(t, utpCtrl.GetInboundPermit)
	testUtpControllerPermitAcquisition(t, utpCtrl.GetOutboundPermit)
}

func testUtpControllerConcurrencyGetPermitAcquisition(t *testing.T, getPermit func() (Permit, bool)) {
	var permitCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			_, ok := getPermit()
			if ok {
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
