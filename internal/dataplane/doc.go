// Package dataplane is the engine: [Engine] runs one space's data plane in
// process (router, rules, wg, path and transport under it), configured by
// one [Engine.Apply] per map. Its subpackages (tun, router, rules, wg,
// path, transport, netcfg, nsthread, firewall, egress, dns, blobs) are
// plain ports and adapters with no DDD aggregates.
//
// OS specifics are per-OS files inside each subpackage. Everything here is
// pure Go, and everything but tun, egress and firewall builds for Android.
//
// # Engine and agent
//
// The engine is in-process wiring only. It owns the ports it drives,
// holding only what it means: the overlay interface's configuration
// ([InterfaceConfigurator]), the route table's want and status
// ([RouteTable]) and what the resolver serves ([Resolver]). netcfg,
// routetable and dns know nothing of them; the agent adapts them and does
// everything else around the engine (package agent; DESIGN.md "Node
// agent"). So the engine's own files (this directory's, tests aside, which
// may drive real adapters) import none of dataplane/netcfg,
// dataplane/routetable, dataplane/dns and dataplane/tun, and nothing here
// imports the agent; depguard enforces both.
//
// # The last Apply's steps
//
// Each Apply records its steps as they end ([Engine.LastApply], for `thinkpol
// diag`): the section read ("section"), the rules compiled ("rules"), with
// a route table the direct routes taken out first ("route_table_shrink"),
// the revocations ("removals"), the overlay interface ("interface", where
// the engine has one), the WireGuard devices ("devices"), the router's table
// ("router") and the route table's final set ("route_table"), each with its
// time from the end of the one before, failed or not, and the step the
// Apply failed at, as Status.LastApplyError. A section that can't run here
// ends after its revocations. Re-compiling the rules outside an Apply
// (SetRules) records nothing.
//
// # The overlay's MTU
//
// The overlay's MTU ([OverlayMTU]) is what the node's links leave after
// the transport, the path header and WireGuard. Links are budgeted as
// IPv6 whatever their endpoint's family, so nodes agree as long as their
// links do: 1328 for unshaped udp over a link MTU of 1500
// ([DefaultLinkMTU]). The overlay MTU is meant to be space-wide, computed
// by the map builder from every link's budget (TP-030); until then each
// node uses the floor of its own links, and a relay drops and counts the
// packets too long for its next link (path.Counters.TooLarge). A link that
// leaves less than [MinOverlayMTU] is skipped rather than holding the node
// back. Where the MTU is below IPv6's minimum of 1280 ([MinIPv6MTU]), the
// overlay carries IPv4 only and the node's status says so
// (Status.IPv6Off).
//
// # The overlay interface after a link event
//
// Linux drops a TUN's IPv6 addresses when its link goes down, and
// something may change its MTU meanwhile. So the engine re-applies the
// TUN's addresses and MTU whenever its link comes up again (the TUN's own
// link events, debounced), not only with the next map, which may be far
// off; a link that is down is left down, and a failed re-apply is retried
// while the link stays up. Status.InterfaceReapplies counts them.
package dataplane
