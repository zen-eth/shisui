package web3

import (
	"runtime"

	"github.com/optimism-java/shisui2/internal/version"
)

type API struct{}

func (p *API) ClientVersion() string {
	// TODO add version
	info, _ := version.VCS()
	name := "Shisui"
	name += "/" + runtime.GOOS + "-" + runtime.GOARCH
	name += "/" + runtime.Version()
	name += "/" + info.Commit + "/" + info.Date
	return name
}
