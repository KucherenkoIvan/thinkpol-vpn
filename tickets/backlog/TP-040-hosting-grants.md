---
id: TP-040
title: "Hosting grants and shared nodes"
milestone: M4
area: features/hosting
repo: thinkpol-vpn
size: epic
depends_on: [TP-036, TP-010]
refs: [A10, N5, N6, N7, DESIGN#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
A node owner shares a server node with another space, fully isolated, capped and revocable.

## Scope (split before starting)
- `HostingGrant` aggregate; offer and accept tokens passed between two controllers.
- The node owner's map lists guest spaces (public key, cap, ingress/egress granted).
- Supervisor starts guest workers and accepts guest envelopes for those workers only.
- Bandwidth caps and fair share between spaces.
- The guest controller's view: shared node as an endpoint plus the grant, read-only.
- Revocation on both sides.

## Notes
- From TP-003's review (decided, not built): the owner's map section for a shared node gets a `HostedSpace` list, each `{space_id, signing key, recovery key, cap, allow_ingress, allow_egress}`; with the guest's keys the supervisor builds a `netmap.Trust` and verifies the guest's envelopes for that guest's worker only.
- Only the owner space's listeners are honored on a shared node: guests can't open ports. The supervisor reads each guest's `Inbound` table from the guest's own map to authenticate the guest's connections on the owner's listeners, and hands them to the guest's worker.
- **From TP-010 (caps):**
  - Implement `supervisor.FairShare` as per-space token buckets. `Allow` must be cheap and non-blocking: it runs per datagram on the listener's goroutine. It sees both directions of datagram traffic. Replays never reach it: they are filtered per credential across every listener of the transport, and across listener reopens (only a supervisor restart starts the history afresh).
  - Handed-over streams bypass it. A pacing rate (`SO_MAX_PACING_RATE`) set on the descriptor before the handoff caps only the node's sends; uploads need policing (tc ingress or IFB on the uplink) or a read-rate limit. Add TP-009's veth and cgroup limits.
  - Guests' `Inbound` come from the guests' own maps (`AcceptedInbound`); only the owner's listeners are opened.
- **From TP-013 (security):** a guest space's inbound table comes from the guest's own map, whose `AllowIngress` must not be trusted. Before `dataplane.AcceptedInbound` on a guest section, replace the section's `AllowIngress` (and `AllowEgress`) with what the owner's map grants that guest (at most what the node allows); then `AcceptsInbound` drops the guest's devices on a node not granted ingress. `netmap.Build`'s `hiddenFromDevices` checks recipients only, so a shared node (not a recipient of the guest map) is the guest builder's to check against the grant.
- **From TP-017 (review S4):** blobs are per space. A guest space's seeds belong in its own directory (e.g. `guests/<space-id>/blobs/`), read by `seedBlobs` for that space's worker only (`supervisor.Space.Seeds`). A worker holds its space's whole header set in memory (at most `blobs.ServerMaxHeldSize`, 16 MiB, plus a stand-in set while lists are replaced): set a per-worker cgroup `MemoryMax` that accounts for it, and count a guest's blobs against the guest's share, not the owner's.
- **From TP-014 (egress), decided in its review:** a guest's `Space.Egress` is the grant's (at most what the node allows), never the guest map's `AllowEgress`, and the guest's worker section gets `AllowEgress` set from the grant before it is handed over (the engine's exit follows the section). A guest's `Dials` are firewall holes its own admin authors: cap them (e.g. 64), take public unicast addresses only and never the node's own, show their count to the owner, and honour them only if the grant allows egress (or the owner's map lists the servers the guest may reach). Each space's flows through the root are capped (`Options.MaxFlowsPerSpace`, a quarter of the conntrack table by default): size it with the number of guests. Per-space egress caps would go on the veth (tc, `WorkerInfo.Link`).

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): HostedSpace shape and listener/inbound rules for shared nodes in Notes
- 2026-10-11 docs (TP-010 review): notes from the shared listener
- 2026-10-12 docs (TP-013 review): notes from the ingress and egress settings
- 2026-10-12 docs (TP-017): notes from blob distribution
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
