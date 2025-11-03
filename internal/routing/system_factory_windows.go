// +build windows

package routing

import (
	"thinkpol-vpn/internal/platform"
	"thinkpol-vpn/internal/tun/windows"
)

func newSystemManager() platform.SystemInterface {
	return windows.NewSystemManager()
}
