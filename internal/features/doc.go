// Package features holds the control plane's bounded contexts (spaces,
// members, nodes, hosting, topology, policy, invites, provisioning,
// publishing, telemetry), one subpackage each, built on go-kernel.
//
// Features never import internal/dataplane: the controller is not a runtime
// dependency of the data plane, and the two meet only through the map.
package features
