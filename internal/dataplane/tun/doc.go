// Package tun creates the overlay interface, the one real TUN of a node's
// data plane (wireguard-go/tun): the router reads and writes it, and the
// WireGuard devices only ever see the router's virtual TUNs. Addresses, MTU
// and routes are netcfg's (OwnerOverlay).
//
// Desktop and server Linux (linux && !android) is implemented. macOS's
// utun is TP-019 and Windows's Wintun TP-047; until then, and on Android,
// whose TUN comes from VpnService, Create returns ErrUnsupported. The
// package is desktop-only: the Android build check leaves it out.
package tun
