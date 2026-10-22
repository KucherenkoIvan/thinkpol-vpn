// Package tun creates the overlay interface, the one real TUN of a node's
// data plane (wireguard-go/tun): the router reads and writes it, and the
// WireGuard devices only ever see the router's virtual TUNs. Addresses, MTU
// and routes are netcfg's (OwnerOverlay).
//
// The agent creates the TUN (its Host's NewTUN) and hands it to the
// engine, whose own files never import this package. The TUN's link
// events reach the engine through the router: Linux drops a TUN's IPv6
// addresses when its link goes down, so the engine re-applies the
// addresses and MTU when the link comes up again (see package dataplane).
//
// Desktop and server Linux (linux && !android) and macOS (utun) are
// implemented. Windows's Wintun is TP-047; until then, and on Android,
// whose TUN comes from VpnService, Create returns ErrUnsupported. The
// package is desktop-only: the Android build check leaves it out.
//
// DefaultName is per OS: "thinkpol0" on Linux; on macOS "utun", which has
// the kernel pick the next free utunN, so callers take the TUN's name
// from Device.Name once it exists.
package tun
