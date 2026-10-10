// Package dataplane moves packets on every node: tun, router, wg, path,
// transport/<name>, egress, dns and telemetry live in subpackages, as plain
// ports and adapters with no DDD aggregates.
//
// No cgo here and no imports from internal/features: the data plane has to
// stay buildable for mobile and must not depend on the control plane.
package dataplane
