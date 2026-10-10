// Package supervisor runs on server nodes: it owns the public address and
// the shared listener, authenticates incoming connections, maps each to its
// space and hands it to that space's worker. See DESIGN.md "Server agent: one
// worker per space".
package supervisor
