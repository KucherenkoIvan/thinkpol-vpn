---
id: TP-075
title: "Agent layer cleanup, part 1"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-019]
refs: [S1, DESIGN#desktop-client]
owner: "agent-glm"
branch: "tp-075-agent-layer-refactor"
---

## Goal
`internal/agent` has one composition root and one map follower so TP-046 can install the service without copying control flow per OS.

## Scope
- A `Platform` struct built in `cmd/` (adapters today are built in `node.go:239`, `dataplane.go:191-211`, `supervisor_linux.go:92`; `cmd/thinkpol/up.go` calls `agent.Prepare` then `node.Adapters(reload)` and optionally appends the local API adapter).
- One `mapFollower` replacing the three copies (`Node.awaitSection`, `serverSpaces.next`, `runner.next`).

## Out of scope
- Status vocabulary, `waitLog` test synchronisation, transport `Router`/`ListenConfig` split, LIFO cleanup stack and depguard on dataplane imports: TP-083.
- New product features; Windows/Android adapters: TP-047 (after this ticket).

## Acceptance
- [x] behaviour unchanged for map follow and adapter wiring: `make lint`, `make test`, `make lab-test` green
- [x] one `mapFollower` with a single `take(envelope)` used from device and server modes

## Notes
- **Split (backlog grooming 2026-10-15):** this ticket is part 1 only. TP-083 takes the rest of the original TP-075 refactor (status vocabulary, `waitLog` removal, cleanup stack, transport split, depguard).
- **Independent review (2026-10-15), file:line evidence (composition root and map follower):** adapters built in `node.go:239`, `dataplane.go:191-211`, `supervisor_linux.go:92` vs `cmd/thinkpol/up.go` (`Prepare`, `Adapters`); map-follow state three times with the same log strings.
- **One `follower.take` (from TP-037 / TP-011):** device mode (`runner.next` in `dataplane.go`) and server mode (`serverSpaces.next` in `node.go`) each run `(*Map).Next` → `openSection` → removed/back-in-space logic. Fold them into one `follower` (current map, section, removed flag) with a single `take(envelope)` both modes call, so the semantics can't drift.
- This is also the architecture correction: the composition root moves from `internal/agent` to `cmd/`, so the data plane's adapters are built and passed in, not built by the core.

## Review findings
- [ ] R2.1 DESIGN.md (~301, "Engine and agent"): the node's host adapters (TUN and its configurator, the route table with the host's leak guard, the resolver configuration, the host lock) are built by the composition root (cmd/thinkpol) per OS and handed to internal/agent; the agent sequences them and never constructs them. Log line saying DESIGN changed.
- [ ] R2.2 Split Platform by who may use it: agent.Host = what one data plane needs of its network stack (NewConfigurator, NewTUN, NewGuard, NewRouteTable, ClearConfig, ClearRouteTable, SetSystemDNS, SystemUpstreams, BlobNet blobs.Net — zero value = real sockets); agent.Platform = Host + host-wide LockHost, RestoreDNS. DataPlane carries Host only; ServeSpace(log, Host); worker.go passes platform().Host. The sandboxed worker must not receive LockHost or a supervisor factory.
- [ ] R2.3 cmd/thinkpol/platform.go is wiring only: every field a reference to an existing function (one type shim for NewRouteTable allowed). The TUN ordering/rollback and the MTU (const tunMTU = 1420) move into runner.start; the owner dispatch of clearing moves into Host (clearNetwork: ClearRouteTable(NewGuard()), then ClearConfig(OwnerOverlay)); keep routetable.New's argument order (guard, log).
- [ ] R2.4 Drop Platform.NewSupervisor: node.go calls supervisor.New with NewRoot from n.plat.NewConfigurator(netcfg.OwnerSupervisor); remove supervisor_linux.go's NewRoot default (unset NewRoot is an error) and its caller-describing comment.
- [ ] R2.5 The transport registry and the device's blob service: build the udp adapter's socket control via Host (e.g. Host.Transports, or the SocketControl as a Host field) and the blob service with blobs.NewOnNet(o, h.BlobNet) — or, if moving Transports is too large, write the deferral into the ticket Notes and DESIGN explicitly; do not leave the Log claiming the correction is complete. Remove the base.Registry == nil test-only fallback in servespace.go if Transports moves. Replace TP-104's newBlobs field hook: BlobNet in Host is the seam; the fastBlobs Limits override stays a private test hook.
- [ ] R2.6 mapFollower is a named field (follow mapFollower), not embedded; serverSpaces gets its own log; one markRemoved(m) owns the removal warning (awaitSection uses it instead of logging itself); drop warnKind (Node.Kind 0 already means no kind).
- [ ] R2.7 Put mode back on awaitSection's "back in space" line (log it after resolveMode, with "mode", n.mode), and after the dropped-connect warning, as before. Test that asserts mode= on that line.
- [ ] R2.8 Tests inject only through Prepare's Platform (no n.tweak overwriting dp.Platform after Prepare); server_test.go checks the removedMsg the code actually uses (not a copy).
- [ ] R2.9 hostlock_unix.go: one doc comment (no stacked old paragraph, no "who wires it").
- [ ] R2.10 The ticket's hook attribution: the remaining private test fields (path, retryAfter, onEngine, dnsPort, Node.tweak) — add a Scope bullet to TP-083 (tickets/backlog/TP-083-*.md, with a Log line) or correct this ticket's Log; blobOptions/newBlobs is this ticket's now (R2.5).
- [ ] R2.11 Nits: comments state constraints, not who calls (platform.go, node.go, dataplane.go, servespace.go, cmd platform.go, tests); validate the whole Platform/Host once in Prepare/ServeSpace or drop the partial nil check and its test-mentioning message; one name clearNetwork; rewrite Log line ~44: "Not verified here: the adapters' host-side paths outside the lab's Linux (macOS device on a real network: needs_human: macos)".

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): milestone M2; split — part 1 (composition root + map follower); TP-083 is part 2
- 2026-10-15 docs (backlog grooming, review fixes): cites and up.go wording; follower semantics from TP-037; Windows dep wording
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-075-agent-layer-refactor
- 2026-10-19 the composition root (cmd/thinkpol's platform()) builds the node's host adapters and hands them to internal/agent as agent.Platform; the package-variable test hooks are gone, tests fake adapters through the same Platform (tweak/onEngine/private fields stay: TP-083)
- 2026-10-19 one mapFollower with a single take(envelope) for Node.awaitSection, serverSpaces and the data plane's runner (device and server modes); log line texts unchanged
- 2026-10-19 merged origin/rewrite (TP-107); TP-104 not merged yet, so no blobs.Net in the Platform
- 2026-10-19 in-progress → review — make lint, make test green; make lab-test green (exit 0, all 35 node packages PASS, lab suite ok) at c38c9d2. Not verified here: the adapters' host-side paths outside the lab's Linux (macOS device on a real network: needs_human: macos)
- 2026-10-19 review → has-errors — review round 2: R2.1–R2.11
- 2026-10-19 has-errors → in-progress — review round 2 findings picked up (R2.1–R2.11)
