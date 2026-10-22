# thinkpol-vpn — Desktop client design

The desktop client: the service, the tray and the local API. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## Desktop client

Two processes. The **service** is the node agent: it runs privileged (TUN, routes, firewall), installed as a launchd daemon, systemd unit or Windows service. The **tray app** is unprivileged and talks to the service over a local socket (named pipe on Windows) with a small gRPC API (the local API, below). The CLI is a third client of the same API. Its UI stack is provisional (TP-086).

A device can be enrolled in several spaces but runs **one at a time**: switching spaces tears down one data plane and brings up the other.

When the entry in use belongs to another space, the tray labels it **`owned by <space>`**: that space's node owner can see the member's IP and traffic volume (see Trust in the PRD).

## The local API

Status, connect and disconnect, spaces, rule presets and the in-memory log, for the CLI and the tray. Connect and disconnect bring a device's data plane up and down while the service keeps following its space's maps; a server serves whenever it runs.

- **Two gates.** The socket's directory admits only root, the service's user and one group; every call then checks the caller's kernel-recorded credentials: the group sees the status and controls the node, the log (whose debug lines may quote the map) is root's only. There is no read-only tier for other users (RR43).
- **The API never takes the VPN down.** If it can't serve, the node runs on without it, retrying.
- **A rule preset chosen through the API** is stored by the service and nothing else writes it; one that can't be read stops the node from starting rather than reading as "no rules".
- **Nothing the API reports is a public address, a key or a secret** (S1, S4): ids are opaque, addresses are the overlay's, failures are named from fixed vocabularies. Clients sanitize every string they receive before showing it. The one exception is root's half of `diag`, a versioned snapshot whose host parts (routes, leak guard, resolvers) name public addresses, never a key or a secret; see [`agent/localapi`](../../internal/agent/localapi/doc.go).

The kill switch is [security](security.md#kill-switch)'s: its design, and the decided crash posture, are there.