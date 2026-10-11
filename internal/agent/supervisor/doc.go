// Package supervisor runs on server nodes: one worker process per space,
// each in its own network, mount and PID namespaces (see package worker),
// wired to the root namespace by a veth pair, restarted with backoff when
// it dies, and never outliving the supervisor. See DESIGN.md "Server agent:
// one worker per space".
//
// Per worker slot n (stable while the space is served, reused after):
//
//	root namespace                         space's namespace
//	tp-space<n>  169.254.100.(4n+1)/30  ── veth0  169.254.100.(4n+2)/30
//	             fd74:7073:7061:<n>::1/64          fd74:7073:7061:<n>::2/64
//	                                       default routes via the root end
//	                                       (netcfg, OwnerSupervisor)
//
// The worker runs as user and group UIDBase+n. The supervisor's nftables
// table (TableName) keeps the spaces apart in the root namespace.
//
// The supervisor also owns the node's public listeners (SetListeners), for
// every space at once. A datagram is authenticated by the transport's
// Router against the merged credential tables of all spaces (Space.Inbound,
// each link stamped with the space it was listed under) and forwarded,
// untouched, to that space's current worker over its data socket, without
// blocking: a full socket drops the datagram, so a stuck worker stalls only
// its own space. The worker's replies come back the same way and leave
// through the public socket, but only to remote ends its own authenticated
// datagrams came from. A stream connection is routed by the start of it
// and its descriptor passed to the worker over the control socket.
// Whatever fails authentication goes to the listener's camouflage and
// never reaches a worker.
package supervisor
