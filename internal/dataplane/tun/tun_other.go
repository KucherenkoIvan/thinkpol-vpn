//go:build (!linux && !darwin) || android

package tun

import wgtun "golang.zx2c4.com/wireguard/tun"

// DefaultName is the overlay interface's name where the OS lets us choose.
const DefaultName = "thinkpol0"

// Create returns ErrUnsupported: this OS's TUN comes with its own ticket.
func Create(name string, mtu int) (wgtun.Device, error) {
	return nil, ErrUnsupported
}
