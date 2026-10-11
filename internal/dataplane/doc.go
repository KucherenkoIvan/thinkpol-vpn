// Package dataplane is the engine that wires the data plane together: tun,
// router, wg, path, transport, netcfg, nsthread, firewall, egress, dns,
// blobs and telemetry are its subpackages, as plain ports and adapters with
// no DDD aggregates. This package does the wiring and nothing else: Engine runs
// one space's data plane in process, configured by one Apply per map. The
// agent does everything around it (creating the TUN and its configurator,
// the transport registry, watching for maps, the listeners) and is never
// imported from here.
//
// OS specifics are per-OS files inside each subpackage. Everything here is
// pure Go, and everything but tun, egress and firewall builds for Android.
package dataplane
