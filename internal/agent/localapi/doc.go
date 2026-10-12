// Package localapi is the node agent's local service API (DESIGN.md
// "Desktop client"): a gRPC service (proto/thinkpol/localapi/v1) on a Unix
// socket that the CLI and the tray app use to see and control the node
// running on the same machine.
//
// Who may use it is decided twice. The socket's directory is the first
// gate: it admits only root (the service's user) and the members of one
// group (`thinkpol`), so anyone else gets "permission denied" when they
// connect. Then every call checks the caller's credentials, as the kernel
// reported them when it connected (SO_PEERCRED and SO_PEERGROUPS on Linux,
// LOCAL_PEERCRED on macOS), against the call's level (Policy): the group's
// members see the status and connect and disconnect; the agent's log,
// whose debug lines may quote the map, is root's only.
//
// What the API reports holds no public address, key or secret (PRD S1,
// S4), and clients sanitize every string they receive before showing it.
package localapi
