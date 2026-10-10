// Package worker runs one space's data plane on a server node, inside that
// space's own namespaces, as `thinkpol worker -space <id>` started by the
// supervisor (see package supervisor and DESIGN.md "Server agent: one worker
// per space").
//
// A worker starts as root in fresh network, mount and PID namespaces, with
// its socket to the supervisor at ipc.WorkerFD. It waits for the
// supervisor's Init (its namespace is wired by then), sandboxes itself:
// fresh /proc and /sys (so it sees only its own processes and interfaces),
// an empty /run, and drops to its own unprivileged user with only the
// capabilities a data plane needs (Capabilities); then it reports Ready and
// serves until the supervisor says Stop or goes away.
package worker
