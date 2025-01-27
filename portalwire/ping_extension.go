package portalwire

import pingext "github.com/zen-eth/shisui/portalwire/ping_ext"

var defaultPingExtentions = []uint16{pingext.ClientInfo, pingext.Error}

var _ pingext.PingExtension = DefaultPingExtension{}

type DefaultPingExtension struct{}

func (h DefaultPingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range defaultPingExtentions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h DefaultPingExtension) Extensions() []uint16 {
	return defaultPingExtentions
}

var historySupportedExtentions = []uint16{pingext.ClientInfo, pingext.HistoryRadius, pingext.Error}
var _ pingext.PingExtension = HistoryPingExtension{}

type HistoryPingExtension struct{}

func (h HistoryPingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range historySupportedExtentions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h HistoryPingExtension) Extensions() []uint16 {
	return historySupportedExtentions
}

var stateSupportedExtentions = []uint16{pingext.ClientInfo, pingext.BasicRadius, pingext.Error}
var _ pingext.PingExtension = StatePingExtension{}

type StatePingExtension struct{}

func (h StatePingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range stateSupportedExtentions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h StatePingExtension) Extensions() []uint16 {
	return stateSupportedExtentions
}

var beaconSupportedExtentions = []uint16{pingext.ClientInfo, pingext.BasicRadius, pingext.Error}

type BeaconPingExtension struct{}

func (h BeaconPingExtension) IsSupported(ext uint16) bool {
	supported := false
	for _, e := range beaconSupportedExtentions {
		if e == ext {
			supported = true
			break
		}
	}
	return supported
}

func (h BeaconPingExtension) Extensions() []uint16 {
	return beaconSupportedExtentions
}
