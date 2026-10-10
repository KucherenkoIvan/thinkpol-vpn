// Package dataplane is the engine that wires the data plane together: tun,
// router, wg, path, transport, netcfg, firewall, egress, dns, blobs and
// telemetry are its subpackages, as plain ports and adapters with no DDD
// aggregates. This package does the wiring and nothing else.
//
// OS specifics are per-OS files inside each subpackage. Everything here is
// pure Go, and everything but tun, egress and firewall builds for Android.
package dataplane
