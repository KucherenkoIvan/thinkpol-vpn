// Package ifbind binds sockets to a network interface, so what they send
// leaves through it or not at all, whatever the routing table says: the
// tunnel's own sockets to the TUN (DNS to an exit, blob fetches), and on
// macOS the links' and the direct DNS upstream's sockets to the physical
// interface, which is how they bypass the TUN there (package routetable's
// SocketControl).
//
// Linux uses SO_BINDTODEVICE (by name), macOS IP_BOUND_IF and
// IPV6_BOUND_IF (by index, looked up by name when none is given);
// elsewhere binding fails, so a socket that must be bound never opens
// unbound (Windows: TP-047; Android needs none, its VpnService protects
// sockets).
//
// [Control] asks for the interface as each socket opens, with the
// socket's family, so a binding can follow an interface that changes: a
// link redialed after the network changed binds to the new physical
// interface. [ByName] is Control for one fixed interface.
//
// # macOS
//
// A socket bound with IP_BOUND_IF never routes by an unscoped route to
// another interface, such as the utun's split routes. It reaches only
// destinations whose own route is on its interface: the interface's
// on-link subnet, routes via its gateway (route-table enforcement's
// endpoint and direct routes) and routes scoped to it (RTF_IFSCOPE). The
// primary interface has no scoped default route of its own, so for
// anything else the kernel answers EHOSTUNREACH (seen on a device:
// `ping -b en0` to a tunneled address). That is why route-table
// enforcement gives each direct DNS upstream a host route scoped to the
// physical interface.
package ifbind
