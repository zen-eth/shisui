package state

import (
	"github.com/zen-eth/shisui/portalwire"
)

type API struct {
	*portalwire.PortalProtocolAPI
}

func (p *API) StateRoutingTableInfo() *portalwire.RoutingTableInfo {
	return p.RoutingTableInfo()
}

func (p *API) StateAddEnr(enr string) (bool, error) {
	return p.AddEnr(enr)
}

func (p *API) StateGetEnr(nodeId string) (string, error) {
	return p.GetEnr(nodeId)
}

func (p *API) StateDeleteEnr(nodeId string) (bool, error) {
	return p.DeleteEnr(nodeId)
}

func (p *API) StateLookupEnr(nodeId string) (string, error) {
	return p.LookupEnr(nodeId)
}

func (p *API) StatePing(enr string, payloadType *uint16, payload *string) (*portalwire.PortalPongResp, error) {
	return p.Ping(enr, payloadType, payload)
}

func (p *API) StateFindNodes(enr string, distances []uint) ([]string, error) {
	return p.FindNodes(enr, distances)
}

func (p *API) StateFindContent(enr string, contentKey string) (interface{}, error) {
	return p.FindContent(enr, contentKey)
}

func (p *API) StateOffer(enr string, contentItems [][2]string) (string, error) {
	return p.Offer(enr, contentItems)
}

func (p *API) StateTraceOffer(enr string, key string, value string) (interface{}, error) {
	return p.TraceOffer(enr, key, value)
}

func (p *API) StateRecursiveFindNodes(nodeId string) ([]string, error) {
	return p.RecursiveFindNodes(nodeId)
}

func (p *API) StateGetContent(contentKeyHex string) (*portalwire.ContentInfo, error) {
	return p.RecursiveFindContent(contentKeyHex)
}

func (p *API) StateLocalContent(contentKeyHex string) (string, error) {
	return p.LocalContent(contentKeyHex)
}

func (p *API) StateStore(contentKeyHex string, contextHex string) (bool, error) {
	return p.Store(contentKeyHex, contextHex)
}

func (p *API) StatePutContent(contentKeyHex, contentHex string) (*portalwire.PutContentResult, error) {
	return p.PutContent(contentKeyHex, contentHex)
}

func (p *API) StateTraceGetContent(contentKeyHex string) (*portalwire.TraceContentResult, error) {
	return p.TraceRecursiveFindContent(contentKeyHex)
}

func NewStateNetworkAPI(portalProtocolAPI *portalwire.PortalProtocolAPI) *API {
	return &API{
		portalProtocolAPI,
	}
}
