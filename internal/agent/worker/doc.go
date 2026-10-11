// Package worker runs one space's data plane on a server node, inside that
// space's own namespaces, as `thinkpol worker -space <id>` started by the
// supervisor (see package supervisor and DESIGN.md "Server agent: one worker
// per space").
//
// A worker starts as the root of a fresh user namespace, with fresh
// network, mount, PID, IPC, UTS and cgroup namespaces inside it, and its
// sockets to the supervisor at ipc.ControlFD and ipc.DataFD. It waits for
// the supervisor's Init (its namespace is wired by then), sandboxes itself
// (a minimal root, only the network capabilities), reports Ready and
// serves until the supervisor says Stop or goes away.
//
// The supervisor owns the node's public listeners. It tells the worker
// which ones serve it (Session.Listeners): a datagram listener is a
// net.PacketConn reading what the supervisor authenticated and forwarded
// over the data socket, whose writes go back out through the public
// socket; a stream listener delivers the connections whose descriptors
// the supervisor passed over the control socket.
package worker
