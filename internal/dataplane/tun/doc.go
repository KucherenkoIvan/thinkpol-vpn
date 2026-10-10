// Package tun creates the overlay interface, the one real TUN of a node's
// data plane (wireguard-go/tun): the router reads and writes it, and the
// WireGuard devices only ever see the router's virtual TUNs. Addresses, MTU
// and routes are netcfg's (OwnerOverlay).
//
// Linux (desktop and server) is implemented; macOS's utun is TP-019 and
// Windows's Wintun TP-047, which return ErrUnsupported until then. Android
// gets its TUN from VpnService, so this package is desktop-only and never
// in the Android build.
package tun
