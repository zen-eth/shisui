package portalwire

import (
	"errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	pingext "github.com/zen-eth/shisui/portalwire/ping_ext"
)

// DiscV5API json-rpc spec
// https://playground.open-rpc.org/?schemaUrl=https://raw.githubusercontent.com/ethereum/portal-network-specs/assembled-spec/jsonrpc/openrpc.json&uiSchema%5BappBar%5D%5Bui:splitView%5D=false&uiSchema%5BappBar%5D%5Bui:input%5D=false&uiSchema%5BappBar%5D%5Bui:examplesDropdown%5D=false
type DiscV5API struct {
	DiscV5 *discover.UDPv5
}

func NewDiscV5API(discV5 *discover.UDPv5) *DiscV5API {
	return &DiscV5API{discV5}
}

type PutContentResult struct {
	PeerCount     int  `json:"peerCount"`
	StoredLocally bool `json:"storedLocally"`
}

type NodeInfo struct {
	NodeId string `json:"nodeId"`
	Enr    string `json:"enr"`
	Ip     string `json:"ip"`
}

type RoutingTableInfo struct {
	Buckets     [][]string `json:"buckets"`
	LocalNodeId string     `json:"localNodeId"`
}

type DiscV5PongResp struct {
	EnrSeq        uint64 `json:"enrSeq"`
	RecipientIP   string `json:"recipientIP"`
	RecipientPort uint16 `json:"recipientPort"`
}

type PortalPongResp struct {
	EnrSeq      uint32      `json:"enrSeq"`
	PayloadType uint16      `json:"payloadType"`
	Payload     interface{} `json:"payload"`
}

type ContentInfo struct {
	Content     string `json:"content"`
	UtpTransfer bool   `json:"utpTransfer"`
}

type TraceContentResult struct {
	Content     string `json:"content"`
	UtpTransfer bool   `json:"utpTransfer"`
	Trace       Trace  `json:"trace"`
}

type Trace struct {
	Origin       string                   `json:"origin"`       // local node id
	TargetId     string                   `json:"targetId"`     // target content id
	ReceivedFrom string                   `json:"receivedFrom"` // the node id of which content from
	Responses    map[string]RespByNode    `json:"responses"`    // the node id and there response nodeIds
	Metadata     map[string]*NodeMetadata `json:"metadata"`     // node id and there metadata object
	StartedAtMs  int                      `json:"startedAtMs"`  // timestamp of the beginning of this request in milliseconds
	Cancelled    []string                 `json:"cancelled"`    // the node ids which are send but cancelled
}

type NodeMetadata struct {
	Enr      string `json:"enr"`
	Distance string `json:"distance"`
}

type RespByNode struct {
	DurationMs    int32    `json:"durationMs"`
	RespondedWith []string `json:"respondedWith"`
}

type EnrsResp struct {
	Enrs []string `json:"enrs"`
}

func (d *DiscV5API) NodeInfo() *NodeInfo {
	n := d.DiscV5.LocalNode().Node()

	return &NodeInfo{
		NodeId: "0x" + n.ID().String(),
		Enr:    n.String(),
		Ip:     n.IP().String(),
	}
}

func (d *DiscV5API) RoutingTableInfo() *RoutingTableInfo {
	n := d.DiscV5.LocalNode().Node()
	bucketNodes := d.DiscV5.Nodes()

	stringBuckets := make([][]string, len(bucketNodes))
	for i, b := range bucketNodes {
		stringBuckets[i] = make([]string, len(b))
		for j, node := range b {
			stringBuckets[i][j] = "0x" + node.Node.ID().String()
		}
	}

	return &RoutingTableInfo{
		Buckets:     stringBuckets,
		LocalNodeId: "0x" + n.ID().String(),
	}
}
func (d *DiscV5API) AddEnr(enr string) (bool, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return false, err
	}

	// immediately add the node to the routing table
	d.DiscV5.AddKnownNode(n)
	return true, nil
}

func (d *DiscV5API) GetEnr(nodeId string) (bool, error) {
	id, err := enode.ParseID(nodeId)
	if err != nil {
		return false, err
	}
	n := d.DiscV5.GetNode(id)
	if n == nil {
		return false, errors.New("record not in local routing table")
	}

	return true, nil
}

func (d *DiscV5API) DeleteEnr(nodeId string) (bool, error) {
	id, err := enode.ParseID(nodeId)
	if err != nil {
		return false, err
	}

	n := d.DiscV5.GetNode(id)
	if n == nil {
		return false, errors.New("record not in local routing table")
	}

	d.DiscV5.DeleteNode(n)
	return true, nil
}

func (d *DiscV5API) LookupEnr(nodeId string) (string, error) {
	id, err := enode.ParseID(nodeId)
	if err != nil {
		return "", err
	}

	enr := d.DiscV5.ResolveNodeId(id)

	if enr == nil {
		return "", errors.New("record not found in DHT lookup")
	}

	return enr.String(), nil
}

func (d *DiscV5API) Ping(enr string) (*DiscV5PongResp, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return nil, err
	}

	pong, err := d.DiscV5.Ping(n)
	if err != nil {
		return nil, err
	}

	return &DiscV5PongResp{
		EnrSeq:        pong.ENRSeq,
		RecipientIP:   pong.ToIP.String(),
		RecipientPort: pong.ToPort,
	}, nil
}

func (d *DiscV5API) FindNodes(enr string, distances []uint) ([]string, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return nil, err
	}
	findNodes, err := d.DiscV5.Findnode(n, distances)
	if err != nil {
		return nil, err
	}

	enrs := make([]string, 0, len(findNodes))
	for _, r := range findNodes {
		enrs = append(enrs, r.String())
	}

	return enrs, nil
}

func (d *DiscV5API) TalkReq(enr string, protocol string, payload string) (string, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return "", err
	}

	req, err := hexutil.Decode(payload)
	if err != nil {
		return "", err
	}

	talkResp, err := d.DiscV5.TalkRequest(n, protocol, req)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(talkResp), nil
}

func (d *DiscV5API) RecursiveFindNodes(nodeId string) ([]string, error) {
	findNodes := d.DiscV5.Lookup(enode.HexID(nodeId))

	enrs := make([]string, 0, len(findNodes))
	for _, r := range findNodes {
		enrs = append(enrs, r.String())
	}

	return enrs, nil
}

type PortalProtocolAPI struct {
	portalProtocol *PortalProtocol
}

func NewPortalAPI(portalProtocol *PortalProtocol) *PortalProtocolAPI {
	return &PortalProtocolAPI{
		portalProtocol: portalProtocol,
	}
}

func (p *PortalProtocolAPI) NodeInfo() *NodeInfo {
	n := p.portalProtocol.localNode.Node()

	return &NodeInfo{
		NodeId: n.ID().String(),
		Enr:    n.String(),
		Ip:     n.IP().String(),
	}
}

func (p *PortalProtocolAPI) RoutingTableInfo() *RoutingTableInfo {
	n := p.portalProtocol.localNode.Node()
	bucketNodes := p.portalProtocol.RoutingTableInfo()

	return &RoutingTableInfo{
		Buckets:     bucketNodes,
		LocalNodeId: "0x" + n.ID().String(),
	}
}

func (p *PortalProtocolAPI) AddEnr(enr string) (bool, error) {
	p.portalProtocol.Log.Debug("serving AddEnr", "enr", enr)
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return false, err
	}
	if n.IPAddr().BitLen() == 0 {
		p.portalProtocol.Log.Warn("ip addr is empty, Enr may contains a multicast ip", "enr", enr)
	}
	p.portalProtocol.AddEnr(n)
	return true, nil
}

func (p *PortalProtocolAPI) AddEnrs(enrs []string) bool {
	// Note: unspecified RPC, but useful for our local testnet test
	for _, enr := range enrs {
		n, err := enode.Parse(enode.ValidSchemes, enr)
		if err != nil {
			continue
		}
		p.portalProtocol.AddEnr(n)
	}

	return true
}

func (p *PortalProtocolAPI) GetEnr(nodeId string) (string, error) {
	id, err := enode.ParseID(nodeId)
	if err != nil {
		return "", err
	}

	if id == p.portalProtocol.localNode.Node().ID() {
		return p.portalProtocol.localNode.Node().String(), nil
	}

	n := p.portalProtocol.table.getNode(id)
	if n == nil {
		return "", errors.New("record not in local routing table")
	}

	return n.String(), nil
}

func (p *PortalProtocolAPI) DeleteEnr(nodeId string) (bool, error) {
	id, err := enode.ParseID(nodeId)
	if err != nil {
		return false, err
	}

	n := p.portalProtocol.table.getNode(id)
	if n == nil {
		return false, nil
	}

	p.portalProtocol.table.deleteNode(n)
	return true, nil
}

func (p *PortalProtocolAPI) LookupEnr(nodeId string) (string, error) {
	id, err := enode.ParseID(nodeId)
	if err != nil {
		return "", err
	}

	enr := p.portalProtocol.ResolveNodeId(id)

	if enr == nil {
		return "", errors.New("record not found in DHT lookup")
	}

	return enr.String(), nil
}

func (p *PortalProtocolAPI) Ping(enr string, payloadType *uint16, payload *string) (*PortalPongResp, error) {
	if payloadType == nil && payload != nil {
		return nil, pingext.ErrPayloadRequired{}
	}

	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return nil, err
	}

	var data []byte
	var defaultType = pingext.ClientInfo

	if payloadType == nil {
		payloadType = &defaultType
	}

	if !p.portalProtocol.PingExtensions.IsSupported(*payloadType) {
		return nil, pingext.ErrPayloadTypeIsNotSupported{}
	}
	if payload == nil {
		data, err = p.portalProtocol.genPayloadByType(*payloadType)
		if err != nil {
			return nil, err
		}
	} else {
		data, err = pingext.JsonTypeToSszBytes(*payloadType, []byte(*payload))
		if err != nil {
			return nil, err
		}
	}

	pong, _, err := p.portalProtocol.pingInnerWithPayload(n, *payloadType, data)
	if err != nil {
		return nil, err
	}

	jsonRes, err := pingext.SszBytesToJson(pong.PayloadType, pong.Payload)
	if err != nil {
		return nil, err
	}

	return &PortalPongResp{
		EnrSeq:      uint32(pong.EnrSeq),
		PayloadType: pong.PayloadType,
		Payload:     jsonRes,
	}, nil
}

func (p *PortalProtocolAPI) FindNodes(enr string, distances []uint) ([]string, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return nil, err
	}
	findNodes, err := p.portalProtocol.findNodes(n, distances)
	if err != nil {
		return nil, err
	}

	enrs := make([]string, 0, len(findNodes))
	for _, r := range findNodes {
		enrs = append(enrs, r.String())
	}

	return enrs, nil
}

func (p *PortalProtocolAPI) FindContent(enr string, contentKey string) (interface{}, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return nil, err
	}

	contentKeyBytes, err := hexutil.Decode(contentKey)
	if err != nil {
		return nil, err
	}

	flag, findContent, err := p.portalProtocol.findContent(n, contentKeyBytes)
	if err != nil {
		return nil, err
	}

	switch flag {
	case ContentRawSelector:
		contentInfo := &ContentInfo{
			Content:     hexutil.Encode(findContent.([]byte)),
			UtpTransfer: false,
		}
		p.portalProtocol.Log.Trace("FindContent", "contentInfo", contentInfo)
		return contentInfo, nil
	case ContentConnIdSelector:
		contentInfo := &ContentInfo{
			Content:     hexutil.Encode(findContent.([]byte)),
			UtpTransfer: true,
		}
		p.portalProtocol.Log.Trace("FindContent", "contentInfo", contentInfo)
		return contentInfo, nil
	default:
		enrs := make([]string, 0)
		for _, r := range findContent.([]*enode.Node) {
			enrs = append(enrs, r.String())
		}

		p.portalProtocol.Log.Trace("FindContent", "enrs", enrs)
		return &EnrsResp{
			Enrs: enrs,
		}, nil
	}
}

func (p *PortalProtocolAPI) Offer(enr string, contentItems [][2]string) (string, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return "", err
	}

	entries := make([]*ContentEntry, 0, len(contentItems))
	for _, contentItem := range contentItems {
		contentKey, err := hexutil.Decode(contentItem[0])
		if err != nil {
			return "", err
		}
		contentValue, err := hexutil.Decode(contentItem[1])
		if err != nil {
			return "", err
		}
		contentEntry := &ContentEntry{
			ContentKey: contentKey,
			Content:    contentValue,
		}
		entries = append(entries, contentEntry)
	}

	transientOfferRequest := &TransientOfferRequest{
		Contents: entries,
	}

	offerReq := &OfferRequest{
		Kind:    TransientOfferRequestKind,
		Request: transientOfferRequest,
	}
	accept, err := p.portalProtocol.offer(n, offerReq, &NoPermit{})
	if err != nil {
		return "", err
	}

	version, err := p.portalProtocol.getOrStoreHighestVersion(n)
	if err != nil {
		return "", err
	}
	// transfer bitlist to []byte
	if version == 0 {
		accept = p.portalProtocol.handleV0Offer(accept)
	}

	return hexutil.Encode(accept), nil
}

func (p *PortalProtocolAPI) TraceOffer(enr string, key string, value string) (interface{}, error) {
	n, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return nil, err
	}

	contentKey, err := hexutil.Decode(key)
	if err != nil {
		return nil, err
	}
	contentValue, err := hexutil.Decode(value)
	if err != nil {
		return nil, err
	}

	transientOfferRequestWithResult := &TransientOfferRequestWithResult{
		Content: &ContentEntry{
			ContentKey: contentKey,
			Content:    contentValue,
		},
		Result: make(chan *OfferTrace, 1),
	}

	offerReq := &OfferRequest{
		Kind:    TransientOfferRequestWithResultKind,
		Request: transientOfferRequestWithResult,
	}

	_, err = p.portalProtocol.offer(n, offerReq, &NoPermit{})
	if err != nil {
		return nil, err
	}

	offerTrace := <-transientOfferRequestWithResult.Result

	return ProcessOfferTrace(offerTrace)
}

func (p *PortalProtocolAPI) RecursiveFindNodes(nodeId string) ([]string, error) {
	findNodes := p.portalProtocol.Lookup(enode.HexID(nodeId))

	enrs := make([]string, 0, len(findNodes))
	for _, r := range findNodes {
		enrs = append(enrs, r.String())
	}

	return enrs, nil
}

func (p *PortalProtocolAPI) RecursiveFindContent(contentKeyHex string) (*ContentInfo, error) {
	contentKey, err := hexutil.Decode(contentKeyHex)
	if err != nil {
		return nil, err
	}
	contentId := p.portalProtocol.toContentId(contentKey)

	data, err := p.portalProtocol.Get(contentKey, contentId)
	if err == nil {
		return &ContentInfo{
			Content:     hexutil.Encode(data),
			UtpTransfer: false,
		}, nil
	}
	p.portalProtocol.Log.Warn("find content err", "contextKey", hexutil.Encode(contentKey), "err", err)

	content, utpTransfer, err := p.portalProtocol.ContentLookup(contentKey, contentId)

	if err != nil {
		return nil, err
	}

	return &ContentInfo{
		Content:     hexutil.Encode(content),
		UtpTransfer: utpTransfer,
	}, err
}

func (p *PortalProtocolAPI) LocalContent(contentKeyHex string) (string, error) {
	contentKey, err := hexutil.Decode(contentKeyHex)
	if err != nil {
		return "", err
	}
	contentId := p.portalProtocol.ToContentId(contentKey)
	content, err := p.portalProtocol.Get(contentKey, contentId)

	if err != nil {
		return "", err
	}
	return hexutil.Encode(content), nil
}

func (p *PortalProtocolAPI) Store(contentKeyHex string, contextHex string) (bool, error) {
	contentKey, err := hexutil.Decode(contentKeyHex)
	if err != nil {
		return false, err
	}
	contentId := p.portalProtocol.ToContentId(contentKey)
	if !p.portalProtocol.InRange(contentId) {
		return false, nil
	}
	content, err := hexutil.Decode(contextHex)
	if err != nil {
		return false, err
	}
	err = p.portalProtocol.Put(contentKey, contentId, content)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (p *PortalProtocolAPI) Gossip(contentKeyHex, contentHex string) (int, error) {
	contentKey, err := hexutil.Decode(contentKeyHex)
	if err != nil {
		return 0, err
	}
	content, err := hexutil.Decode(contentHex)
	if err != nil {
		return 0, err
	}
	id := p.portalProtocol.Self().ID()
	return p.portalProtocol.Gossip(&id, [][]byte{contentKey}, [][]byte{content})
}

func (p *PortalProtocolAPI) PutContent(contentKeyHex, contentHex string) (*PutContentResult, error) {
	contentKey, err := hexutil.Decode(contentKeyHex)
	if err != nil {
		return nil, err
	}
	content, err := hexutil.Decode(contentHex)
	if err != nil {
		return nil, err
	}
	shouldStore, err := p.portalProtocol.ShouldStore(contentKey, content)
	if err != nil {
		return nil, err
	}
	id := p.portalProtocol.Self().ID()
	gossipedNodes, err := p.portalProtocol.GossipReturnNodes(&id, [][]byte{contentKey}, [][]byte{content})
	if err != nil {
		if errors.Is(err, ErrNoGossipNodes) {
			gossipedNodes = []*enode.Node{}
		} else {
			return nil, err
		}
	}
	num := len(gossipedNodes)

	gossipedNodeIDs := make(map[enode.ID]struct{})
	for _, node := range gossipedNodes {
		gossipedNodeIDs[node.ID()] = struct{}{}
	}

	// If gossip didn't reach the target number of peers (e.g., 8),
	// perform a DHT lookup for nodes close to the content ID and offer directly.
	const targetPeerCount = 8
	if num < targetPeerCount {
		contentIdBytes := p.portalProtocol.toContentId(contentKey)
		var contentId enode.ID
		copy(contentId[:], contentIdBytes)

		lookupNodes := p.portalProtocol.Lookup(contentId)

		// Filter out nodes that were already gossiped to
		nodesToOffer := make([]*enode.Node, 0, len(lookupNodes))
		for _, node := range lookupNodes {
			if _, exists := gossipedNodeIDs[node.ID()]; !exists {
				nodesToOffer = append(nodesToOffer, node)
			}
		}

		if len(nodesToOffer) > 0 {
			offerReq := &OfferRequest{
				Kind: TransientOfferRequestKind,
				Request: &TransientOfferRequest{
					Contents: []*ContentEntry{
						{
							ContentKey: contentKey,
							Content:    content,
						},
					},
				},
			}

			// Offer to additional nodes until the target count is reached or no more nodes are found.
			needed := targetPeerCount - num
			offeredCount := 0
			for _, nodeToOffer := range nodesToOffer {
				if offeredCount >= needed {
					break
				}

				if nodeToOffer.ID() == p.portalProtocol.Self().ID() {
					continue
				}

				_, offerErr := p.portalProtocol.offer(nodeToOffer, offerReq, &NoPermit{})
				if offerErr != nil {
					p.portalProtocol.Log.Warn("Failed to offer content to lookup node", "node", nodeToOffer.ID(), "err", offerErr)
					continue
				}
				num++
				offeredCount++
				// Add successfully offered node to the map to avoid re-offering if somehow listed again
				gossipedNodeIDs[nodeToOffer.ID()] = struct{}{}
			}
		}
	}

	return &PutContentResult{
		PeerCount:     num,
		StoredLocally: shouldStore,
	}, nil
}

func (p *PortalProtocolAPI) TraceRecursiveFindContent(contentKeyHex string) (*TraceContentResult, error) {
	contentKey, err := hexutil.Decode(contentKeyHex)
	if err != nil {
		return nil, err
	}
	contentId := p.portalProtocol.toContentId(contentKey)
	return p.portalProtocol.TraceContentLookup(contentKey, contentId)
}

// SuccessResult represents a successful offer with content keys
type SuccessResult struct {
	Success string `json:"Success"`
}

func ProcessOfferTrace(trace *OfferTrace) (interface{}, error) {
	switch trace.Type {
	case Success:
		return SuccessResult{
			Success: hexutil.Encode(trace.ContentKeys),
		}, nil
	case Declined:
		return "Declined", nil
	case Failed:
		return "Failed", nil
	default:
		return nil, errors.New("unknown trace type")
	}
}
