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
// table (TableName) keeps the spaces apart in the root namespace. The
// supervisor also owns the public address and the shared listener, and
// hands each authenticated connection to its space's worker over the
// worker's socket (package ipc); that part is TP-010's.
package supervisor
