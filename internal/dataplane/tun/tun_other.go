//go:build !linux || android

package tun

import wgtun "golang.zx2c4.com/wireguard/tun"

// Create returns ErrUnsupported: this OS's TUN comes with its own ticket.
func Create(name string, mtu int) (wgtun.Device, error) {
	return nil, ErrUnsupported
}
