// Package egress finds the way a server's internet traffic leaves it: the
// uplink the root namespace's default routes use, and the families it
// carries. Linux-only, and not on Android.
//
// # Egress on a server
//
// A node whose section allows egress is its space's exit through Linux's
// own forwarding and nftables NAT (masquerade, NAT66 for IPv6), in two
// places: the space's worker namespace, which forwards and SNATs the
// space's traffic to its transit address, and the root namespace, which
// masquerades the transit ranges out of the uplink to the node's public
// address. Both are the supervisor's tables (package supervisor, under
// "Egress"). Only a worker is an exit: its engine writes what peers send
// for the internet to its TUN (dataplane.EngineConfig.Forward makes the
// overlay device one of router.Table's Forward egresses, relaxing the
// Local check for destinations outside the overlay networks; other overlay
// destinations are still dropped), while a node in device mode never sets
// Forward and never forwards, whatever its section says. A userspace
// TCP/IP stack is a later alternative.
//
// # The uplink
//
// [FindUplink] takes the interface of the preferred IPv4 default route in
// the main table (lowest metric; a multipath route by its first next hop),
// or of the IPv6 one on a node without IPv4. IPv6 counts only when an IPv6
// default route leaves by that same interface and it has a global IPv6
// address (not link-local or unique local): NAT66 masquerades to it, and a
// unique local address is no internet. One uplink carries both families.
// No default route at all is [ErrNoUplink]: no internet to egress to. The
// supervisor asks again on every change of its spaces and whenever the
// root namespace's default routes change.
package egress
