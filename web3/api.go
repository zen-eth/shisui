package web3

import (
	"github.com/zen-eth/shisui/internal/version"
)

type API struct{}

func (p *API) ClientVersion() string {
	return version.ClientInfo()
}
