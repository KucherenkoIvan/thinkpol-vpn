// Package routetable enforces routing rules in the OS routing table
// (DESIGN.md "Routing rules and DNS", route-table mode): everything enters
// the TUN except the rules' direct destinations and the links' endpoints,
// which leave through the physical default route.
//
// Config is the layout as netcfg configuration (on Linux, policy routing:
// a table of its own and two rules per family); an Enforcer applies it
// through a netcfg configurator of OwnerRouteTable and keeps it in place
// as routing changes. SocketControl marks the transports' sockets so
// links bypass the tunnel whatever the table holds.
package routetable
