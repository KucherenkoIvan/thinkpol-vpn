// +build darwin

package routing

import (
	"thinkpol-vpn/internal/platform"
	"thinkpol-vpn/internal/tun/darwin"
)

func newSystemManager() platform.SystemInterface {
	return darwin.NewSystemManager()
}
