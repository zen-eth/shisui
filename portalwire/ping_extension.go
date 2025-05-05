package portalwire

import pingext "github.com/zen-eth/shisui/portalwire/ping_ext"

var defaultPingExtensions = []uint16{pingext.ClientInfo, pingext.Error}

var _ pingext.PingExtension = DefaultPingExtension{}

type DefaultPingExtension struct{}

func (h DefaultPingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range defaultPingExtensions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h DefaultPingExtension) Extensions() []uint16 {
	return defaultPingExtensions
}

// LatestMutuallySupportedBaseExtension intentionally returns nil to indicate
// that DefaultPingExtension does not support any base extensions.
func (h DefaultPingExtension) LatestMutuallySupportedBaseExtension(extensions []uint16) *uint16 {
	return nil
}

var historySupportedExtensions = []uint16{pingext.ClientInfo, pingext.HistoryRadius, pingext.Error}
var baseExtensions = []uint16{pingext.HistoryRadius}

var _ pingext.PingExtension = HistoryPingExtension{}

type HistoryPingExtension struct{}

func (h HistoryPingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range historySupportedExtensions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h HistoryPingExtension) Extensions() []uint16 {
	return historySupportedExtensions
}

func (h HistoryPingExtension) LatestMutuallySupportedBaseExtension(extensions []uint16) *uint16 {
	for _, baseExt := range baseExtensions {
		for _, ext := range extensions {
			if ext == baseExt {
				foundExt := baseExt
				return &foundExt
			}
		}
	}
	return nil
}

var stateSupportedExtensions = []uint16{pingext.ClientInfo, pingext.BasicRadius, pingext.Error}
var stateBaseExtensions = []uint16{pingext.BasicRadius}

var _ pingext.PingExtension = StatePingExtension{}

type StatePingExtension struct{}

func (h StatePingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range stateSupportedExtensions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h StatePingExtension) Extensions() []uint16 {
	return stateSupportedExtensions
}

func (h StatePingExtension) LatestMutuallySupportedBaseExtension(extensions []uint16) *uint16 {
	for _, baseExt := range stateBaseExtensions {
		for _, ext := range extensions {
			if ext == baseExt {
				foundExt := baseExt
				return &foundExt
			}
		}
	}
	return nil
}

var beaconSupportedExtensions = []uint16{pingext.ClientInfo, pingext.BasicRadius, pingext.Error}
var beaconBaseExtensions = []uint16{pingext.BasicRadius}

type BeaconPingExtension struct{}

func (h BeaconPingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range beaconSupportedExtensions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h BeaconPingExtension) Extensions() []uint16 {
	return beaconSupportedExtensions
}

func (h BeaconPingExtension) LatestMutuallySupportedBaseExtension(extensions []uint16) *uint16 {
	for _, baseExt := range beaconBaseExtensions {
		for _, ext := range extensions {
			if ext == baseExt {
				foundExt := baseExt
				return &foundExt
			}
		}
	}
	return nil
}
