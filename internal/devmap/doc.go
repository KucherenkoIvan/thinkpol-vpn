// Package devmap is development tooling: signed maps made by hand from a
// YAML spec, until the controller builds them (M4). It backs `thinkpol dev
// keygen` and `thinkpol dev map`, and prints what `thinkpol dev lists
// build` built (WriteListsReport).
//
// # Spec
//
// A spec lists a space's nodes and the paths between them; everything else
// in the map is derived. [Reference] is the annotated format (`thinkpol
// dev map spec` prints it):
//
//	space:                      # optional
//	  name: home                # overlay names <node>.home.internal (devices)
//	  ipv4: 100.64.0.0/10       # overlay IPv4 network, inside 100.64.0.0/10 (default)
//	  ipv6: fd12:3456:789a::/48 # ULA /48; default: the space's own, from space.key
//	lists:                      # optional: GeoIP list blobs (`dev lists build`)
//	  - name: ru
//	    file: lists/ru.geoip    # relative to the spec's directory
//	nodes:
//	  - name: server-1          # also names the node's key files
//	    kind: server            # server | device
//	    ipv4: 100.64.0.1        # optional, as is ipv6
//	    endpoints:              # what other nodes dial: transport://ip:port
//	      - udp://192.0.2.1:4500
//	      - udp://[2001:db8::1]:4500
//	    listen:                 # optional, derived from endpoints
//	      - udp://0.0.0.0:4500
//	    ingress: true           # devices may connect (servers; default false)
//	    egress: true            # internet traffic may leave (servers; default false)
//	  - name: device-a
//	    kind: device
//	    lists: [ru]             # optional: the lists the node uses
//	paths:                      # [one end, relays..., other end]
//	  - [device-a, server-1]
//	  - [device-a, server-1, device-b]
//	rules:                      # optional, every device's: first match wins
//	  - domain-suffix:example.ru -> direct
//	  - default -> chain:nl
//	chains:
//	  - {name: nl, exit: server-3}   # a server with egress: true
//	presets: {domestic: ru, chain: nl}   # optional: what the presets use
//
// Values may use ${NAME}, filled from the environment by `dev map build`,
// for addresses known only at run time (the lab's, which Docker assigns).
// Errors name the file, line and column of what is wrong.
//
// # Derivation
//
//   - Addresses: nodes without a fixed overlay address get the lowest free
//     host address of the network, in spec order. The IPv6 network is the
//     spec's, else the random ULA /48 `dev keygen space` stored in
//     space.key.
//   - Listeners: without listen, one per transport, port and address family
//     of the node's endpoints, bound to every address of the family
//     (0.0.0.0 or ::). Only servers have endpoints and listeners.
//   - Peers: the two ends of a path are WireGuard peers. Each gets its
//     neighbour on the path as a candidate first hop; several paths between
//     the same ends add first hops in the order the paths are written,
//     which is the order failover follows.
//   - Routes: each node inside a path (a server: devices don't relay)
//     routes to both ends through its neighbours. Routes in which a packet
//     could go round in circles, following any next hop toward one
//     destination, are refused.
//   - Links: every pair of neighbours on a path is linked once. A device
//     dials the server, which must have ingress on, so no device's section
//     has the address of a server with ingress off; of two servers, the one
//     declared first dials. The
//     dialer's link lists all of the other node's endpoints; the dialed node
//     gets an inbound link per transport.
//   - Credentials: one random secret per link and transport, fresh on every
//     build: the dialer's credential and, udp being symmetric, the
//     listener's verifier.
//   - Names: with a space name, each device's section holds it, the
//     device's own name and its peers' (a node is named only to the
//     devices that have it as a peer); servers' sections hold no names.
//   - Rules: every device's section gets the space's rules and chains;
//     each device needs a path to every chain's exit.
//   - Ids: random, made by `dev keygen node` and kept in the node's files.
//   - Lists: ReadLists reads each list's file and checks it is a GeoIP list
//     blob. The header lists every list, unnamed (the availability set
//     servers hold and pass on); a node's section names the lists in its
//     lists. Nodes fetch the blobs from their peers, so some node needs a
//     copy in its state directory (blobs/<hex SHA-256>).
//
// # Keys
//
// A key directory holds space.key (space id, IPv6 network and signing key,
// private), space.pub (the trust anchor: space id, signing and recovery
// public keys) and, per node, <name>.key (id, map and WireGuard private
// keys, for that node only) and <name>.pub (id and public keys, all the map
// builder reads). recovery.key (private) belongs offline. Private files are
// written 0600 and refused when others can read them; no file is ever
// replaced, and a keygen run writes all its files or none. Each file is a
// few `field: "value"` lines.
//
// This package is development tooling for cmd/thinkpol only (depguard):
// the node agent reads its keys and maps with its own code.
package devmap
