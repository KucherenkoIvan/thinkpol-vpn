package tun

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// DefaultName has the kernel pick the utun's unit: the TUN is utunN for
// the first free N, which Device.Name reports.
const DefaultName = "utun"

// Create creates a utun with an MTU of mtu: name is "utun" (the next free
// unit) or "utunN". The utun is point-to-point, so its addresses don't
// route their networks into it: netcfg's darwin adapter adds those routes.
// Closing it removes the interface, and with it every route through it.
func Create(name string, mtu int) (wgtun.Device, error) {
	d, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun: create %s: %w", name, err)
	}
	return d, nil
}
