// Package netcfg configures the host side of the overlay: interface
// addresses, MTU, link state, routes (in any table, unicast, throw or
// unreachable) and policy rules, which route-table enforcement of routing
// rules builds on (package routetable). Configurator is the port (contract
// in its doc); New returns the adapter for this OS, one file per OS.
//
// Every configurator works for an Owner (overlay, supervisor, route
// table), one live configurator per owner and network namespace. The Linux
// adapter speaks netlink, can work on another network namespace
// (NewInNamespace), tags routes and rules with the owner's route protocol
// (84, 85, 86), and holds an exclusive flock per namespace and owner under
// LockDir, so routes and rules with its protocol that it finds are a dead
// predecessor's.
package netcfg
