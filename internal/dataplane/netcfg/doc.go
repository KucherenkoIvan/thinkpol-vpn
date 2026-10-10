// Package netcfg configures the host side of the overlay: interface
// addresses, MTU, link state and routes, which route-table enforcement of
// routing rules builds on. Configurator is the port (contract in its doc);
// New returns the adapter for this OS, one file per OS.
//
// Every configurator works for an Owner (overlay, supervisor, route
// table), one live configurator per owner and network namespace. The Linux
// adapter speaks netlink, can work on another network namespace
// (NewInNamespace), tags routes with the owner's route protocol (84, 85,
// 86), and holds an exclusive flock per namespace and owner under LockDir,
// so routes with its protocol that it finds are a dead predecessor's.
package netcfg
