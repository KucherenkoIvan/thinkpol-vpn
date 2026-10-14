// Package router sits between the overlay interface (the TUN) and the
// WireGuard devices, one per egress (DESIGN.md "Data plane"). It reads every
// packet the TUN hands it, classifies it by destination with a
// longest-prefix match, and queues it on the chosen egress: a virtual
// tun.Device that one WireGuard device reads as its own TUN. Packets a
// WireGuard device writes go straight back to the TUN.
//
// Destinations inside the space's overlay networks are classified by the
// overlay table alone (one route per peer address), before any rule, so a
// rule can never send an overlay address to an exit; an overlay address no
// peer has is dropped. Everything else is classified by the rules
// (dataplane/rules compiles them into Table.Rules); a route without an
// egress blocks, and a Direct route drops what route tables should have
// kept out of the TUN.
//
// On macOS a packet for the node's own overlay address comes out of the
// utun (the OS routes the point-to-point interface's own address into it):
// the router writes it back into the TUN, so the OS delivers it to itself
// (Table.ReflectLocal), the way Tailscale does on macOS.
//
// The router owns the TUN: closing it closes the TUN. It never looks at
// what a WireGuard device writes back: WireGuard already dropped anything
// whose source its peer isn't allowed.
package router
