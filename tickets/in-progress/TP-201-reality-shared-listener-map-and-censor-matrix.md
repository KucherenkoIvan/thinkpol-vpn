---
id: TP-201
title: "Reality behind the shared listener, in the map and in the censor matrix"
milestone: M2
area: dataplane/transport
stream: transports
repo: thinkpol-vpn
size: L
depends_on: [TP-087]
refs: [C2, C4, docs/design/transports.md#transports, docs/design/server-agent.md#server-agent-one-worker-per-space]
owner: "agent-tp-201"
branch: "tp-201-reality-shared-listener"
---

## Goal
`reality` runs on real nodes and faces the censor lab: a server node serves it through its shared listener, the short id choosing the space; the map and `thinkpol dev map` describe reality endpoints; and the matrix shows whether it passes M2's gate. TP-087 built the adapter (client, standalone listener, conformance, stock-Xray check); this ticket puts it where a server node and the lab can use it.

## Scope
1. `reality` as a `transport.StreamRoutable`: the supervisor-side router opens the session id and keeps the replay cache, so it can tell the space from the ClientHello before any TLS is terminated; the worker's `HandoffListener` runs REALITY's server on the handed-off connection, which needs the listener's settings in the shared-listener IPC message (supervisor and worker packages). Whatever the router or REALITY's server refuses is spliced to the target, raw and whole.
2. The agent's transport registry and `thinkpol dev map` spec support for reality endpoints and keys (listener key and target, server names, the device's server public key and fingerprint, short ids as credentials).
3. A lab camouflage-target container (a lab site serving TLS 1.3) that reality's listener splices to and that TP-026's prober and server-hello comparison can point at.
4. The censor-matrix rows for `reality`, TP-188's wireguard-rhythm cell included, probed for at least two rekey periods with default settings; if that cell fails, a minimal padding/batching default.

## Out of scope
- The JA3S/JA4S server-hello comparison and the active prober themselves: TP-026 (this ticket only gives them a target to point at).
- Full flow shaping beyond the minimal default: after the MVP.
- Moving the session-id open into the gatekeeper: TP-088.
- Running the full M2 matrix and committing `lab/RESULTS.md`: TP-029.

## Acceptance
- [ ] a server node serves `reality` through its shared listener: the short id selects the space and the connection is handed to that space's worker, which completes REALITY's handshake; a wrong short id and a replay are spliced to the target raw and whole (lab test)
- [ ] the agent's transport registry knows `reality`, and `thinkpol dev map` writes reality endpoints, keys and short ids that a node and a device link with
- [ ] a lab camouflage-target container, reachable without the internet, that reality's listener splices to and TP-026's prober can point at
- [ ] the censor-lab matrix has rows for `reality`
- [ ] the wireguard-rhythm cell's probe runs on `reality` for at least two WireGuard rekey periods (up to about 7 minutes; up to about 10 minutes when the transport batches records; see lab/censor/doc.go) with the transport's default settings, and passes; if it failed first, the fix is a minimal padding/batching default and the Log says so

## Notes
- Split from TP-087 (owner-approved, 2026-11-08): items (1)–(4) of TP-087's proposed split. Matrix rows need (1)–(3) first: a server node always serves through the supervisor.
- What "`reality` passes" means at M2 (owner, 2026-11-07): the lab's handshake-level checks (blocklists, VPN fingerprints, entropy, the active prober, the server-hello fingerprint) and no WireGuard rhythm (TP-188: 2-minute rekey pair, fixed-size keepalive records inside TLS). Flow shape beyond that is not tested at M2. If it fails TP-188's check with default settings, the fix is a minimal padding/batching default, not a full shaping module.
- The wireguard-rhythm cell's probe runs for at least two WireGuard rekey periods (up to about 7 minutes; up to about 10 minutes when the transport batches records; see lab/censor/doc.go) with the transport's default settings, so a pass means the rhythm was looked for (a ~30 s probe passes trivially).
- MPL rule (TP-087's decision, owner 2026-11-07): REALITY's server is `github.com/xtls/reality` as an unmodified Go module, pinned (commit 8cdf7bf, the newest whose go.mod says go 1.24; later ones need Go 1.27). Its MPL-2.0 files are never copied, vendored or patched into this MIT tree; it is used only through its exported API. Xray-core is not a dependency.
- The router's open is ours (TP-087's Notes): same rules as REALITY's server (key-share choice, HKDF, AES-GCM), and only then is the connection handed to `reality.Server` in the worker. Both say no → both splice. `reality.Server` type-asserts `CloseWrite` on its connection, so a wrapper replaying bytes already read must implement it.
- The lab never reaches the internet at test time: the camouflage target is a lab container, and any image is pinned by version and digest and built or pulled under the Docker lock.
- TP-087's lab check covers our dialer against stock Xray only; our listener is checked against our dialer, not a stock Xray client.
- From TP-087 review round 1: cut serve at the router/handoff line: the replay cache is admitted only in the router (a worker re-checking the handed-off hello would reject it as a replay); detect runs where REALITY's Server runs (the worker), not in the supervisor; apply splits into the router's short-id table and the listener's live links; endpoint validation moves into the port so udp and reality agree (reality rejects port 0 and unspecified addresses, udp accepts them).
- From TP-087 review round 2: reality's Listen fails on a target whose certificate the node's roots don't verify (a TLS dial per server name, through Control). The lab camouflage-target container needs `reality.Options.TrustTargetRoots` plumbed for lab nodes (a test/lab-only field the map never sets), or a lab CA in the node image. With the pool only, REALITY's own detection still verifies against the system roots, so the lab target is imitated without post-handshake records; a lab CA in the node image avoids that.

## Log
- 2026-11-08 created in backlog (split from TP-087, owner-approved)
- 2026-11-08 notes: where to cut serve, from TP-087 review round 1
- 2026-11-09 notes: the lab target needs Options.TrustTargetRoots or a lab CA, from TP-087 review round 2
- 2026-11-09 backlog → in-progress, owner: agent-tp-201
