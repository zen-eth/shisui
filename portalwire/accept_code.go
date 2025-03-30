package portalwire

type AcceptCode uint8

const (
	Accepted AcceptCode = iota
	GenericDeclined
	AlreadyStored
	NotWithinRadius
	RateLimited      // rate limit reached. Node can't handle anymore connections
	InboundRateLimit // inbound rate limit reached for accepting a specific content_id, used to protect against thundering herds
	Unspecified
)
