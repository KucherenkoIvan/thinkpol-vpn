---
id: TP-017
title: "Blob distribution through the overlay"
milestone: M1
area: dataplane/blobs
repo: thinkpol-vpn
size: M
depends_on: [TP-011, TP-016]
refs: [R9, A9]
owner: agent-tp-017
branch: tp-017-blob-distribution
---

## Goal
Nodes get the list files (and later releases) referenced by their map from peers, without any outside server.

## Scope
- Simple request/response service on overlay addresses: fetch blob by hash.
- Verify the hash, cache in the state dir, serve cached blobs to peers.
- Fetch on map change; keep serving the previous version until the new one is verified.

## Acceptance
- [x] in the lab, a device without the list fetches it from a server node — `lab/blobs_test.go` `TestBlobDistribution` (map `lab/maps/blobs.yaml`): device-a's section names `geoip:ru` (built by `dev lists build` from a CSV fixture), server-1 runs in server mode with the list seeded in its state directory; device-a logs `blob fetched … peer=<server-1>` (served by server-1's sandboxed worker) and keeps it as `blobs/<sha256>` (0600, directory 0700); server-1's state directory is unchanged
- [x] a corrupted blob is rejected and fetched again from another peer — same test: server-2 (first in device-a's peer order) answers on its overlay address with junk of the right size; device-a logs `blob rejected: the peer sent something else; trying another peer … peer=<server-2>`, then fetches from server-1. A byte flipped in device-a's stored copy is rejected at the next start (`stored blob rejected`) and fetched again. Unit: `TestATamperedBlobIsRejectedAndFetchedFromAnotherPeer`, `TestATamperedStoredBlobIsReplaced`, `TestAPeerAnnouncingTheWrongLengthIsRejected`

## Notes
**Decisions** (as of the review fixes):
- **Transport: TCP on overlay addresses, not a path-layer frame kind.** Inside WireGuard the far end is the peer WireGuard authenticated, TCP gives reliability, flow control and resumption, and the traffic is ordinary tunnel data. A path-layer frame kind would reach link neighbours (relays without WireGuard peers too) but needs its own reliability and chunking; every node that holds or needs blobs has WireGuard peers (devices ↔ servers; the controller's node, M4, is everyone's peer). Port `blobs.Port` = 4717.
- **Servers serve, devices only fetch** (review B1). `DataPlane.ServeBlobs` is set in a server's worker only: it holds the header's whole set and listens on its overlay addresses; a device (and a server run with `-mode device`) holds its section's blobs and runs no listener. Listening and dialing sockets are bound to the TUN (`SO_BINDTODEVICE`; none on Android, where VpnService routes the app's sockets and no listener runs). Linux delivers a local process's connection to the TUN's address as if through the TUN, so the service also closes, unanswered, any connection whose source isn't one of its plan's peers' overlay addresses (`Status.NotPeer`); through the tunnel every source is a peer's (WireGuard's allowed IPs). Per-peer connection limits count by peer id.
- **Protocol** (doc.go): request `"TPB" | 1 | sha256[32] | offset[8 BE]`; response `status[1]` (0 ok, 1 not here, 2 busy, 3 bad request) then for ok `length[8 BE]` = size − offset and the bytes. One request per connection. Unknown and not-held are the same "not here", so no oracle beyond the availability set. The client refuses any length but its map's (a protocol violation is a rejection). Uncompressed on the wire.
- **Checks** (`blobs.Check`): size and SHA-256 against the map's `BlobRef`; a GeoIP list also `lists.Decode`s. Unknown kinds are held and passed on by hash; a held blob whose kind changes in a new map is checked again as that kind (S5). A blob matching its hash that doesn't decode is the map's fault: failed, not retried until the map changes.
- **Plans** (`blobs.PlanFrom(header, section, ipv6, iface, serve)`): the section's blobs the header lists with the same kind and size, the first of each kind and name (the rest reported in `Plan.Skipped` and logged, N2); peers in map order at their overlay addresses inside the space's networks (IPv4 first, IPv6 while carried); `Local` the fetch sources, `Listen` only when serving.
- **Cache** (DESIGN "Node safety", `internal/agent/state.go`): `blobs/` in the state directory, under its rules (owner, no group/other write, no symlinks, atomic writes through `trustedDir.write`). **Devices write it** (`diskBlobs`): the blobs they use (named), plus `index` (kind, name, hex sha, size per line), pruned to what the map names once all its blobs are held, the directory removed with the last. A disconnected device keeps them; removal from the space prunes them. **Servers only read it** (`seedBlobs`): seeds put there by provisioning (`install -m 600 ru.geoip /var/lib/thinkpol/blobs/$(sha256sum ru.geoip | cut -c1-64)`), checked against the map; `supervisor.Space.Seeds` reads them when they are sent (a worker's start, a new config), and each goes to the worker once as its own sealed memfd (`ipc.KindBlob`, protocol version 4) ahead of the config: nothing in the worker config (back to version 1) or kept by the supervisor (S4). The worker holds them in `worker.Seeds`, dropping those a new map doesn't name; what it fetches stays in its memory.
- **The previous version** (`Service.Latest`, S2): a list in use stays until its successor is verified: after a new map (stand-in while the map names a blob of the same kind and name) and after a device's restart (stand-ins loaded once per plan from the store's index). The engine uses it through `EngineConfig.StandIn` (I1).
- **Bounds** (`blobs.Limits`): 16 MiB a blob; a map's blobs together 16 MiB in a worker (`ServerMaxHeldSize`), 64 MiB on a device (`MaxHeldSize`); the map builder keeps the header within 16 MiB (N3, `devmap.ReadLists`/`Plan`; `seedBlobs` too). Each transfer, either way, gets `DialTimeout + size/MinRate` (15 s + size at 16 KiB/s) in all, and a new map abandons the one under way (B2, `Status.Abandoned`); a transfer that breaks after progress resumes from its offset (up to 3 times) from the same peer. Serving: 16 connections, 2 per peer, 2 MiB/s shared; rounds with something missing back off 2 s → 1 min.
- **Engine** (I1, TP-015 merged first): `RunDataPlane` feeds `EngineConfig.Blobs` (`Service.Get`) and `StandIn` (`Service.Latest`), and calls `Engine.ReloadRules` on every `Service.Subscribe` signal (one channel per consumer, also on renames, N1).
- **Status** (`blobs.Status`): counts only, telemetry-safe. Logs: `blob fetched`, `blob rejected …`, `stored blob rejected …`, `blob transfer abandoned`, `previous blob in use until its successor is verified`, with the hash's first 6 bytes, kind, name and the peer's node id.
- **devmap**: spec `lists: [{name, file}]` and per node `lists: [ru]`; `devmap.ReadLists` (called by `dev map build`) reads, decodes and bounds them; servers that devices dial need `ingress: true` (TP-013).

**Tests:** `internal/dataplane/blobs` over loopback standing in for the overlay, the server seeing each dialer's overlay address (fetch; tampered peer then a good one; tampered store; previous version until the successor, also after a restart from the index; relay holding and passing on the whole set; not-here, bad offset, other version; resume; wrong length; limits; undecodable list; busy per peer; non-peers get nothing; a trickling peer abandoned; a new map abandoning a stalled transfer; kind change re-checked; every subscriber signalled, renames too; devices listen nowhere; rate limiter; `Check`; `PlanFrom`), `-race -count=10` clean. `internal/agent`: a device fetching from a worker's seeds and its rules taking the list, removal pruning `blobs/`, disconnect keeping it, `diskBlobs` (index, prune, modes, symlink and writable-directory refusals, a stand-in surviving a restart), `seedBlobs`, a server's seeds not riding in its config. `internal/agent/supervisor` (lab): seeds reach the worker intact, one memfd each, and new ones with a new config. `internal/dataplane`: rules keep the previous list until its successor arrives. Lab `TestBlobDistribution`: the acceptance above, then the blob port answers a peer through the tunnel in full, gives a process in the worker's namespace nothing, has no listener on a device or a device-mode server, and isn't reached by a neighbour routing to overlay addresses by LAN addresses (v4 and v6; control listeners prove the routes).

**Downstream:** notes copied into TP-015, TP-018, TP-022, TP-036, TP-037, TP-038, TP-040, TP-041, TP-044. Platform note for TP-019/TP-047 (not asked to be copied): `internal/dataplane/blobs` `bindTo` refuses on darwin/windows until they bring `IP_BOUND_IF`/`IP_UNICAST_IF`; devices only dial, so that's the dial side.

## Review findings
Review: fix first (cache integrity held up). Orchestrator decisions:
- [x] B1 Privacy: devices never listen (`Plan.Listen` nil for NodeDevice). Servers get blobs from seeds or from other servers. Update the server-from-device test and DESIGN ("every node serves" → servers serve; devices only fetch) — `DataPlane.ServeBlobs` (worker only); `PlanFrom(…, serve)`; DESIGN "Lists"; the server-from-device test is now a device fetching from a server (`TestTheDataPlaneFetchesAndKeepsBlobs`); non-peers closed unanswered
- [x] B2 Trickle DoS: overall per-transfer deadline (DialTimeout + Size/minRate, minRate ~16 KiB/s) and cancel on map generation change; test with a trickling peer; a stalled fetch never blocks other blobs indefinitely — `Limits.MinRate`, per-transfer deadline both ways, `fetchContext` cancelled by `Update`; `TestATricklingPeerIsAbandoned`, `TestANewMapAbandonsAStalledTransfer`
- [x] S1 accept(): close the listener before close(done) so retries can rebind — `accept` closes the listener before `done`
- [x] S2 Persist the held set's index (kind, name, sha) next to the blobs on devices; load stand-ins from it at start so the previous list survives a restart until its replacement is verified. Test: map v2 names ru=B, restart offline, Latest(geoip, "ru") returns A — `Store.Index`, `blobs/index`, `loadStandIns`; `TestThePreviousListSurvivesARestart`, `TestAStoredListOutlivesARestartUntilItsSuccessorArrives`
- [x] S3 Lab test that port 4717 is unreachable from outside the tunnel (route to the device's/server's overlay address via its LAN IP from a neighbour, v4 and v6 → refused/timeout), and from a local process (lo) — lab `TestBlobDistribution/the_blob_port_answers_only_peers_through_the_tunnel` (found that local processes reach a TUN-bound listener: hence device mode never serves and non-peers get nothing)
- [x] S4 Memory: MaxHeld for servers 16 MiB (devices keep 64); don't keep seed bytes in the stored worker config — one memfd per blob sent once; TP-040 Notes: per-worker MemoryMax (cgroup) and account guest blobs — `ServerMaxHeldSize`, `supervisor.Space.Seeds`, `ipc.KindBlob`, `worker.Seeds`, config v1; `TestSeedsReachTheWorker`; TP-040 Notes
- [x] S5 Re-run Check when a held hash's kind changes (or key held blobs on sha+kind) — `Update` re-checks; `TestAHeldBlobIsCheckedAgainUnderAnotherKind`
- [x] N1 One Changed() channel per consumer (Subscribe), signal on rename — `Service.Subscribe`; `TestEverySubscriberHearsOfChanges`
- [x] N2 Dedupe same kind+name in PlanFrom (first wins, report the rest) — `Plan.Skipped`; `TestPlanFrom`
- [x] N3 Enforce the 64 MiB total consistently in ReadLists/Plan/seed — `ReadLists`/`Plan` at 16 MiB (the header, what servers hold), `seedBlobs` the same
- [x] N4 Per-peer limit keyed by Peer.ID — `admit` keys by peer id
- [x] N5 Android: skip the SO_BINDTODEVICE path cleanly (no warning loop); Android has no listeners after B1 — `bind_android.go`
- [x] N6 A server section run with -mode device doesn't write the header set to disk — only named blobs are stored; device mode never takes the header set
- [x] I1 TP-015 integration: wire the blob service into its engine Blobs hook and call ReloadRules on change if TP-015 is on rewrite at the end; otherwise precise Notes in both tickets — TP-015 merged first: wired (`EngineConfig.Blobs`, new `StandIn`, `ReloadRules` on change)
- [x] I2 Downstream notes copied into TP-015, TP-018, TP-022, TP-036, TP-037, TP-038, TP-040, TP-041, TP-044 (one Log line each) — done, one Log line each

## Log
- 2026-10-10 created in backlog
- 2026-10-12 backlog → in-progress — owner: agent-tp-017, branch: tp-017-blob-distribution
- 2026-10-12 in-progress → review — make lint, make test, make test-race and make lab-test pass (TestBlobDistribution); DESIGN.md "Lists" and "Node safety" updated (blob protocol; blobs/ in the state directory: written by devices, read-only seeds on servers)
- 2026-10-12 review → has-errors — review findings B1, B2, S1–S5, N1–N6, I1, I2
- 2026-10-12 has-errors → in-progress — owner: agent-tp-017
