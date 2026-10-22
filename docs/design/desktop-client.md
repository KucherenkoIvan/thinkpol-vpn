# thinkpol-vpn — Desktop client design

The desktop client: the service, the tray and the local API, the kill switch, and the node agent around the engine. The entry point is [DESIGN.md](../../DESIGN.md).

### Desktop client

Two processes. The **service** is the node agent: it runs privileged (TUN, routes, firewall), installed as a launchd daemon, systemd unit or Windows service. The **tray app** is unprivileged and talks to the service over a local socket (named pipe on Windows) with a small gRPC API (the local API, below). The CLI is a third client of the same API. Its UI stack is provisional (TP-086).

A device can be enrolled in several spaces but runs **one at a time**: switching spaces tears down one data plane and brings up the other.

When the entry in use belongs to another space, the tray labels it **`owned by <space>`**: that space's node owner can see the member's IP and traffic volume (see Trust in the PRD).

#### The local API

Status, connect and disconnect, spaces, rule presets and the in-memory log, for the CLI and the tray. Connect and disconnect bring a device's data plane up and down while the service keeps following its space's maps; a server serves whenever it runs.

- **Two gates.** The socket's directory admits only root, the service's user and one group; every call then checks the caller's kernel-recorded credentials: the group sees the status and controls the node, the log (whose debug lines may quote the map) is root's only. There is no read-only tier for other users (RR43).
- **The API never takes the VPN down.** If it can't serve, the node runs on without it, retrying.
- **A rule preset chosen through the API** is stored by the service and nothing else writes it; one that can't be read stops the node from starting rather than reading as "no rules".
- **Nothing the API reports is a public address, a key or a secret** (S1, S4): ids are opaque, addresses are the overlay's, failures are named from fixed vocabularies. Clients sanitize every string they receive before showing it.

#### Kill switch

While on and the tunnel is down, the firewall (pf, nftables, Windows Filtering Platform) allows only traffic to entry nodes, plus LAN when allow-LAN is set. A pause option covers captive portals. The IPv6 leak guard is the connection's, not the kill switch. Not built yet (RR17).

**After a crash the device fails closed by default** under the "everything" and "all but domestic" presets (opt-out): the firewall's rules stay in place when the agent dies without disconnecting, so an unattended crash or failed update leaks nothing, and they come out when the agent starts again and connects. A crash is the likeliest mass-exposure event, and the member least able to notice it is the one who never touched a setting (PRD Decisions, "Crash posture"). A **deliberate disconnect** is different and follows the kill-switch toggle (off by default, D4): the guard comes out, and the traffic goes direct unless the toggle is on. macOS must meet this too. Until the kill switch exists (TP-048), IPv4 flows after a crash (RR18).


### Node agent

The data-plane engine is in-process wiring, configured by one call per map. It owns the ports it drives and imports no host adapter; everything around it is the agent's: following the space's maps, building the transports, running the listeners, and sequencing the host's adapters, which the composition root picks per OS.

- **One node agent per host.** Before anything of the node touches the host, the agent takes the host's agent lock, because a second agent's start-time cleanups would undo the running agent's routes and resolver configuration.
- **A removed node idles, it doesn't fail.** A valid newer map without a section for the node stops its data plane; the agent stays up following the space's maps and starts again when a later map includes it, and a node that finds itself removed at start starts idle the same way, rather than being restarted over and over by its service manager.
- **A device's connection is one state with its transitions** (PRD Decisions, "Agent modelling"): a move its state can't make is refused and logged as a bug. What happens to a node is told as typed events, once per edge, not on every retry that fails again.
