// Package agent is the server node agent: the supervisor that owns the
// public address and the shared listener, and one worker per space, each in
// its own Linux network namespace. See DESIGN.md "Server agent: one worker
// per space".
package agent
