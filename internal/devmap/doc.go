// Package devmap is development tooling: signed maps made by hand from a
// YAML spec, until the controller builds them (M4). It backs `thinkpol dev
// keygen` and `thinkpol dev map`.
//
// # Spec
//
// A spec lists a space's nodes and the paths between them; everything else
// in the map is derived. [Reference] is the annotated format (`thinkpol
// dev map spec` prints it):
//
//	space:                      # optional
//	  ipv4: 100.64.0.0/10       # overlay IPv4 network, inside 100.64.0.0/10 (default)
//	  ipv6: fd12:3456:789a::/48 # ULA /48; default derived from the space id
//	nodes:
//	  - name: server-1          # also names the node's key files
//	    kind: server            # server | device
//	    ipv4: 100.64.0.1        # optional, as is ipv6
//	    endpoints:              # what other nodes dial: transport://ip:port
//	      - udp://192.0.2.1:4500
//	      - udp://[2001:db8::1]:4500
//	    listen:                 # optional, derived from endpoints
//	      - udp://0.0.0.0:4500
//	  - name: device-a
//	    kind: device
//	paths:                      # [one end, relays..., other end]
//	  - [device-a, server-1]
//	  - [device-a, server-1, device-b]
//
// Values may use ${NAME}, filled from the environment by `dev map build`,
// for addresses known only at run time (the lab's, which Docker assigns).
// Errors name the file, line and column of what is wrong.
//
// # Derivation
//
//   - Addresses: nodes without a fixed overlay address get the lowest free
//     host address of the network, in spec order.
//   - Listeners: without listen, one per transport, port and address family
//     of the node's endpoints, bound to every address of the family
//     (0.0.0.0 or ::).
//   - Peers: the two ends of a path are WireGuard peers. Each gets its
//     neighbour on the path as a candidate first hop; several paths between
//     the same ends add first hops in the order the paths are written,
//     which is the order failover follows.
//   - Routes: each node inside a path (a server: devices don't relay)
//     routes to both ends through its neighbours on the path.
//   - Links: every pair of neighbours on a path is linked once. The node
//     without endpoints dials the one with; when both have endpoints, the
//     one declared first dials. The dialer's link lists all of the other
//     node's endpoints; the dialed node gets an inbound link per transport.
//   - Credentials: one random secret per link and transport, fresh on every
//     build: the dialer's credential and, udp being symmetric, the
//     listener's verifier.
//   - Ids: a node's id is a hash of the space id and its map public key, so
//     it is stable while the keys are, and the map is opaque without them.
//
// # Keys
//
// A key directory holds space.key (space id and signing key, private),
// recovery.key (private, to keep offline), space.pub (the trust anchor:
// space id, signing and recovery public keys) and, per node, <name>.key
// (map and WireGuard private keys, for that node only) and <name>.pub (their
// public halves, all the map builder reads). Private files are written
// 0600, and no file is ever replaced. Each is a few "field: hex" lines.
package devmap
