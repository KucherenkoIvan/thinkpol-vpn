// Package netcfg configures the host side of the overlay: interface
// addresses, MTU, link state and routes, which route-table enforcement of
// routing rules builds on. Configurator is the port (contract in its doc);
// New returns the adapter for this OS, one file per OS.
//
// The Linux adapter speaks netlink, can work on another network namespace
// (NewInNamespace), tags its routes with RouteProtocol, so its routes are
// told apart from everyone else's in the kernel, and holds a shared flock on
// the namespace file, so a new configurator knows whether proto-84 routes
// belong to a live one or to a crashed one.
package netcfg
