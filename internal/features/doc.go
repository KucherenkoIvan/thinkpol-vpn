// Package features holds no code: each control plane bounded context
// (spaces, members, nodes, hosting, topology, policy, invites, provisioning,
// publishing, telemetry) is a subpackage following go-kernel's service
// structure, with its admin panel pages in <feature>/adapters/http.
//
// Features never import dataplane, agent or each other; cross-feature calls
// go through shared/ports. Each feature adds a depguard rule saying so.
package features
