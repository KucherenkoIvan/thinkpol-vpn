// Package netcfg configures the host side of the overlay: interface
// addresses, MTU, link state and routes, which route-table enforcement of
// routing rules builds on. Configurator is the port (contract in its doc);
// New returns the adapter for this OS, one file per OS.
//
// The Linux adapter speaks netlink, can work on another network namespace
// (NewInNamespace) and tags its routes with RouteProtocol, so its routes are
// told apart from everyone else's in the kernel.
package netcfg
