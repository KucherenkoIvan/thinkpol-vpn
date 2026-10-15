// Package routetable enforces routing rules in the OS routing table
// (DESIGN.md "Routing rules and DNS", route-table mode): everything enters
// the TUN except the rules' direct destinations and the links' endpoints,
// which leave through the physical default route.
//
// Config is the layout as netcfg configuration (on Linux, policy routing:
// a table of its own and rules per family, PolicyRouting; on macOS, split
// routes in the main table, SplitRoutes); an Enforcer applies it
// through a netcfg configurator of OwnerRouteTable and keeps it in place
// as routing changes. SocketControl marks the transports' sockets (Linux)
// or binds them to the physical interface (macOS) so links bypass the
// tunnel whatever the table holds.
package routetable
