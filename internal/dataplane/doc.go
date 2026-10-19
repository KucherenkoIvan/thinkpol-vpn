// Package dataplane is the engine: Engine runs one space's data plane in
// process (router, rules, wg, path and transport under it), configured by
// one Apply per map. Its subpackages (tun, router, rules, wg, path,
// transport, netcfg, nsthread, firewall, egress, dns, blobs) are plain
// ports and adapters with no DDD aggregates. The engine owns its ports to
// the host (InterfaceConfigurator, RouteTable, Resolver); the agent adapts
// netcfg, routetable and dns to them, creates the TUN, builds the transport
// registry, watches for maps and runs the listeners, and is never imported
// from here.
//
// OS specifics are per-OS files inside each subpackage. Everything here is
// pure Go, and everything but tun, egress and firewall builds for Android.
package dataplane
