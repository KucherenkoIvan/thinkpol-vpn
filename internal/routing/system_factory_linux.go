// +build linux

package routing

import (
	"thinkpol-vpn/internal/platform"
	"thinkpol-vpn/internal/tun/linux"
)

func newSystemManager() platform.SystemInterface {
	return linux.NewSystemManager()
}
