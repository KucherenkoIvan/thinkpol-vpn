---
id: TP-112
title: "Exit DNS: follow-ups from TP-098's review"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-098]
refs: [R4, DESIGN#dns]
owner: "cursor-glm-tp-112"
branch: "tp-112-exit-dns-follow-ups"
---

## Goal
The exit-DNS code says what it does and handles the cases the review found.

## Scope
- The "running inside a worker" signal reuses `DataPlane.Forward` (`internal/agent/resolver.go` ~27-29, ~40; `servespace.go` ~117): give it its own field set only by `serveSpace` (e.g. `inWorker`), assert `serveSpace` sets it, and use it in the tests instead of `Forward`.
- `DESIGN.md` "Upstreams" bullet reads out of order and "those sockets" has no antecedent: direct upstream first (with its socket-mark sentence), then tunnel-bound names (a device's resolver binds its sockets to the exit to the TUN), then the exit's upstreams; "not asked" instead of "left out … never silently dropped".
- The defaults' reason is stated in five places (`resolver.go` ~18-24, ~190-207; `dataplane.go` ~72-76; `workerconfig.go` ~27-28): point the code at DESIGN instead; drop the "sandbox can't read" reason, which contradicts DESIGN.
- Removing the node from its space clears the refused count but not `refusedLogged` (`node.go` ~506): reset both, so rejoining with the same refused set logs again; add the test for the removal path.
- Defaults ignore the families the uplink carries: on an IPv4-only exit the dead Quad9 IPv6 entry is tried second and can stall past the device's 2 s timeout (`resolver.go` ~196-223; `dns/handle.go` ~165). Order or filter the defaults by the families the supervisor's egress carries.
- A server without egress still counts refused upstreams and reports `dns_upstream_refused`, though no device asks its resolver: report it only for exits.
- The refusal log's hint suggests `-egress-allowed` for every refused upstream, including metadata addresses (`resolver.go` ~226): don't suggest opening link-local/metadata.
- Nits: drop the redundant loop in `TestAWorkerResolvesThroughTheDefaultPublicUpstreams` after the exact-list check; `supervisor/isolation_test.go` uses neutral public addresses, not the agent's defaults; `isolation_linux.go` ~273 uses `slices.Concat` instead of `append` on the shared `egressBlocked`.

## Out of scope
- New exit-DNS behaviour beyond what TP-098 shipped; only review follow-ups listed above.

## Acceptance
- [x] each scope item fixed or answered in the Log
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: TP-098's final review round (2026-10-18), split under the three-round cap.

## Review findings
Round 1 (2026-10-21): correctness, design and a second-opinion review.
- [ ] R1.1 `neverOpenable` (resolver.go) misses the metadata services `supervisor/isolation.go` names: `fd00:ec2::254`, `168.63.129.16` (also Azure's DNS, the likeliest `-dns-upstream`), `100.100.100.200`; and never-routable `0.0.0.0/8`, `240.0.0.0/4`. Move the check into the supervisor next to `egressBlocked` (e.g. an exported `EgressMustStayClosed(addr)`) so it can't drift from the policy; the hint offers `-egress-allowed` only when it is false. Its comment must not claim the metadata services are link-local. Test each named address and a private one.
- [ ] R1.2 Family order: an IPv6-only exit now waits 2 × 2 s on two dead IPv4 entries. Ordering (not filtering) can't empty the list: when `s.sup.Egress()` reports exactly one family, stable-sort the defaults so it comes first; otherwise keep the static order. Test IPv4-only, IPv6-only and both. Fix the comment ("an exit whose uplink lacks a family") to match.
- [ ] R1.3 `DataPlane.InWorker` → unexported `inWorker`: "set only by serveSpace" is then enforced by the package.
- [ ] R1.4 The `make lint` box is ticked while the Log says lint fails. TP-116 (toolchain go1.26.10) fixes vulncheck; once it is in `rewrite`, merge `rewrite` into this branch and record a green `make lint`.
- [ ] R1.5 DESIGN.md "Upstreams": a refused upstream is named in health and the log on an exit only (a server without egress reports nothing); the defaults read "Quad9 then Cloudflare over IPv4, then both over IPv6, port 53"; keep "(on Linux and macOS; elsewhere they fail)" for the TUN-bound sockets (`ifbind_other.go`).
- [ ] R1.6 A non-exit with every configured upstream refused still warns "the worker's egress refuses every configured one" on each start (`newResolver`), and the comment "workerUpstreams refused every one and logged each" is false there. Make the warning and comment true for both cases.
- [ ] R1.7 Untested: an exit that loses `AllowEgress` with a refused set clears the count and `refusedLogged` (deleting those two resets fails no test). Add it.
- [ ] R1.8 The exit predicate is raw `AllowEgress`; the engine and netmap use `Kind == NodeServer && AllowEgress` (`MayEndAChain`). Use that.
- [ ] R1.9 Stale text: `status.go` (~59, ~171) calls `DNSUpstreamsRefused` "a server's" (now an exit's); `tickets/backlog/TP-083-…` (~42) says `DataPlane.Forward` keeps a worker off the host's resolvers (now `inWorker`).
- [ ] R1.10 Nits: drop the comment above the `InWorker` check in `newResolver` (it repeats the field's doc); `buildEditing` says it edits node a only (rename or take the node) and `build` calls it instead of copying it; `dnsWorkerConfig`'s comment says "falls back from" (a worker never falls back); rename `…IsReportedNotSilentlyDropped` to match DESIGN's "not asked".

## Log
- 2026-10-18 created in backlog (TP-098 review round 3)
- 2026-10-21 backlog → in-progress — owner: cursor-glm-tp-112, branch: tp-112-exit-dns-follow-ups
- 2026-10-21 inWorker: `DataPlane.InWorker` set only by serveSpace (next to `dp.Forward`), read by newResolver, tests use it; a serveSpace test asserts it (60ade3e)
- 2026-10-21 DESIGN.md "Upstreams" rewritten in order (direct upstream with its socket-mark sentence, tunnel-bound names, the exit's upstreams; "not asked"); the defaults' reason now lives only there, the code points at it and the "sandbox can't read" reason is dropped (5226b2d)
- 2026-10-21 defaults ordered IPv4 first (9.9.9.9, 1.1.1.1, 2620:fe::fe, 2606:4700:4700::1111); not filtered by the uplink's families: the supervisor knows them (Options.Uplink → egress.Uplink) but only as a probed snapshot of Egress(), taken concurrently with SetSpaces and possibly a transient no-uplink, so filtering the worker config by it could empty the defaults; the detection wasn't built. Why the order fixes the stall: dns.Server.exchange tries the upstreams in order (dns/handle.go) and each exchange is bounded by Options.Timeout, 2 s by default (dns/server.go), so a dead-family entry burns a full timeout before the next resolver; with both IPv4 entries first, an IPv4-only exit reaches a second working resolver without the dead family in between (fe982af)
- 2026-10-21 refused upstreams are counted and logged only for an exit (the section's AllowEgress); a non-exit's resolver still gets none of them. Both tested (fe982af)
- 2026-10-21 the refusal hint names -egress-allowed only for a private upstream; never for loopback, link-local, multicast, the unspecified or a zoned address (neverOpenable). Both tested (fe982af)
- 2026-10-21 removing the node from its space resets refusedLogged with the refused count; the rejoin test warns again on the same refused set (fe982af)
- 2026-10-21 nits: the redundant loop after the exact-list check is dropped; isolation_test.go uses documentation-range addresses; isolation_linux.go's slices.Concat was already in place, nothing to do (fe982af, 43d19e4)
- 2026-10-21 mutation checks: wrong family order fails the exact-list test; dropping the reset fails the rejoin test; dropping the exit guard fails the non-exit test; neverOpenable returning false fails the hint test
- 2026-10-21 make test and make lab-test pass (lab run on 43d19e4, 35 packages); make lint passes everything but vulncheck, which fails on a pre-existing Go stdlib vulnerability (GO-2026-6809, crypto/x509 of the local go1.26.9 toolchain, reached from lab/prototypes/reality, untouched by this branch; fixed in go1.26.10) — bumping the pinned toolchain is outside this ticket
- 2026-10-21 in-progress → review
- 2026-10-21 review → has-errors (round 1: R1.1–R1.10)
