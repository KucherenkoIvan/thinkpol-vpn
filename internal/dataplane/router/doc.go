// Package router sits between the overlay interface (the TUN) and the
// WireGuard devices, one per egress (docs/design/overlay.md "Data plane"). It reads every
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
// # Local reflection (macOS)
//
// A utun is point-to-point with its own IPv4 address as the peer, so
// macOS routes what it sends to that address into the utun instead of
// delivering it: without help, the node's own processes never reach a
// service on its overlay address, its resolver included (DESIGN.md
// "DNS"). With [Table.ReflectLocal] (set on macOS only; elsewhere the OS
// never hands the TUN such packets), the router writes a packet read
// from the TUN whose source and destination are both the node's own
// addresses back into the TUN, and the OS takes it in as its own, the
// way Tailscale does on macOS. Anything else for a local address (a
// source injected on the TUN, a peer's address) is never delivered as if
// WireGuard had authenticated it.
//
// macOS can hand the utun such packets with incomplete transport
// checksums, so they are recomputed on the way back ([checksum.Fix]): the
// IPv4 header checksum always, the TCP, UDP or ICMP(v6) checksum when the
// packet is whole. Fragmented IPv4 keeps its transport checksum (its
// header checksum is still fixed); IPv6 with a fragment header is left
// completely unchanged. Reflected packets are written one at a time (a
// TUN with offloads may coalesce a batch in place) and counted
// ([Counters].Reflected, [Counters].ReflectFailed).
//
// The router owns the TUN: closing it closes the TUN. It never looks at
// what a WireGuard device writes back: WireGuard already dropped anything
// whose source its peer isn't allowed.
package router
