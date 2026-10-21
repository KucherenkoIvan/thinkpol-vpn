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
- [x] R1.1 `neverOpenable` (resolver.go) misses the metadata services `supervisor/isolation.go` names: `fd00:ec2::254`, `168.63.129.16` (also Azure's DNS, the likeliest `-dns-upstream`), `100.100.100.200`; and never-routable `0.0.0.0/8`, `240.0.0.0/4`. Move the check into the supervisor next to `egressBlocked` (e.g. an exported `EgressMustStayClosed(addr)`) so it can't drift from the policy; the hint offers `-egress-allowed` only when it is false. Its comment must not claim the metadata services are link-local. Test each named address and a private one.
- [x] R1.2 Family order: an IPv6-only exit now waits 2 × 2 s on two dead IPv4 entries. Ordering (not filtering) can't empty the list: when `s.sup.Egress()` reports exactly one family, stable-sort the defaults so it comes first; otherwise keep the static order. Test IPv4-only, IPv6-only and both. Fix the comment ("an exit whose uplink lacks a family") to match.
- [x] R1.3 `DataPlane.InWorker` → unexported `inWorker`: "set only by serveSpace" is then enforced by the package.
- [x] R1.4 The `make lint` box is ticked while the Log says lint fails. TP-116 (toolchain go1.26.10) fixes vulncheck; once it is in `rewrite`, merge `rewrite` into this branch and record a green `make lint`.
- [x] R1.5 DESIGN.md "Upstreams": a refused upstream is named in health and the log on an exit only (a server without egress reports nothing); the defaults read "Quad9 then Cloudflare over IPv4, then both over IPv6, port 53"; keep "(on Linux and macOS; elsewhere they fail)" for the TUN-bound sockets (`ifbind_other.go`).
- [x] R1.6 A non-exit with every configured upstream refused still warns "the worker's egress refuses every configured one" on each start (`newResolver`), and the comment "workerUpstreams refused every one and logged each" is false there. Make the warning and comment true for both cases.
- [x] R1.7 Untested: an exit that loses `AllowEgress` with a refused set clears the count and `refusedLogged` (deleting those two resets fails no test). Add it.
- [x] R1.8 The exit predicate is raw `AllowEgress`; the engine and netmap use `Kind == NodeServer && AllowEgress` (`MayEndAChain`). Use that.
- [x] R1.9 Stale text: `status.go` (~59, ~171) calls `DNSUpstreamsRefused` "a server's" (now an exit's); `tickets/backlog/TP-083-…` (~42) says `DataPlane.Forward` keeps a worker off the host's resolvers (now `inWorker`).
- [x] R1.10 Nits: drop the comment above the `InWorker` check in `newResolver` (it repeats the field's doc); `buildEditing` says it edits node a only (rename or take the node) and `build` calls it instead of copying it; `dnsWorkerConfig`'s comment says "falls back from" (a worker never falls back); rename `…IsReportedNotSilentlyDropped` to match DESIGN's "not asked".
Round 2 (2026-10-21): correctness, design and a second-opinion review.
- [x] R2.1 `EgressMustStayClosed` is documented as a block ("EgressAllowed may never name", "stay closed even when EgressAllowed names them") that nothing enforces: config accepts such prefixes, `EgressRefused` checks `allowed` first, the root jumps to accept before the drops, and DESIGN says EgressAllowed may name exceptions. Keep this ticket's scope: rename it for what it is (e.g. `EgressNotWorthAllowing`: the addresses the refusal hint never suggests opening), make its comment and test comment say nothing stops an operator from allowing them, and point `egressBlocked`'s comment at it instead of listing the metadata hosts twice ("Each is also inside egressBlocked."). Enforcing it is a separate decision, filed as a backlog ticket.
- [x] R2.2 IPv4-mapped forms slip through: `::ffff:168.63.129.16` (and the other mapped metadata, loopback and link-local addresses) is refused but gets the `-egress-allowed` hint. `Unmap()` first. Test the mapped forms, and that widening a metadata host to its whole range would fail the test (e.g. an address in `100.64.0.0/10` other than `100.100.100.200` stays hint-able, or say why not).
- [x] R2.3 A test that every address the check names is inside `egressBlocked` (narrowing a blocked prefix must fail a test), and the agent's hint test covers a named metadata host, not only `169.254.169.254`.
- [x] R2.4 The family order never reaches a running worker: `serveSpace` takes `DNSUpstreams` from the first config only, so a later order (or a later `-dns-upstream` set) is dropped until the worker restarts. Pass a changed `DNSUpstreams` from later configs into the running resolver (`dns.Server.SetUpstreams`), with a test through `serveSpace`. An uplink change alone doesn't re-run `apply`: don't build that hook here; say in DESIGN and the Log that the order follows the uplink as of the last map applied.
- [x] R2.5 One `Egress()` read per `apply`, passed to both `workerUpstreams` and `egressAttrs`, so the order and the "map applied" log line agree.
- [x] R2.6 The non-exit's no-upstream warning still contradicts its comment and DESIGN ("reports nothing"): warn only when the section `MayEndAChain()`, debug otherwise, and update the comment and `TestServeSpace` to match.
- [x] R2.7 DESIGN.md "Upstreams": add "; the uplink's family first when it carries only one" (and R2.4's "as of the last map applied").
- [x] R2.8 `buildEditing(…, s.b, …)` swaps a and b and then sends the sections to the wrong keys. Edit a pointer to the chosen section instead of swapping.
- [x] R2.9 Nits: `uplinkFamilyOrder` → a verb name (e.g. `orderForUplink`) that always returns a copy; delete the parenthetical "(workerUpstreams refused every one and logged each)" in `resolver_test.go`; an `exitSpaces(t, ups...)` test helper instead of the same exit setup three times.

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
- 2026-10-21 has-errors → in-progress (round 1 findings)
- 2026-10-21 R1.1 the never-openable check moved into the supervisor as EgressMustStayClosed, next to egressBlocked: the metadata services it names (fd00:ec2::254, 168.63.129.16, 100.100.100.200) and the never-routable 0.0.0.0/8 and 240.0.0.0/4 added to loopback, link-local, multicast, the unspecified and zoned; the hint offers -egress-allowed only when it is false; its comment no longer calls the metadata services link-local. Tested: each named address, a metadata one, and private and public ones stay openable (fa6f180)
- 2026-10-21 R1.2 when s.sup.Egress() reports exactly one family the defaults are stable-sorted so it comes first (uplinkFamilyOrder); otherwise the static order stands; the comment matches. Tested IPv4-only, IPv6-only, both, and no uplink (fa6f180)
- 2026-10-21 R1.3 DataPlane.InWorker is the unexported inWorker, set only by serveSpace (fa6f180)
- 2026-10-21 R1.4 merged rewrite (TP-116, toolchain go1.26.10) into the branch: origin/rewrite hadn't received it yet, the merge commit 54154d6 was on the local rewrite, so that was merged (9e63e99); make lint green afterwards, recorded below
- 2026-10-21 R1.5 DESIGN.md Upstreams: the defaults read "Quad9 then Cloudflare over IPv4, then both over IPv6, port 53"; a refused upstream is named in health and the log on an exit only, a server without egress reports nothing; "(on Linux and macOS; elsewhere they fail)" kept for the TUN-bound sockets (fa6f180)
- 2026-10-21 R1.6 the no-upstream warning says the egress refuses every configured one (true for an exit and a non-exit alike), and its comment says an exit's are counted and logged while a non-exit's resolver reports nothing (fa6f180)
- 2026-10-21 R1.7 test: an exit losing AllowEgress clears the count and refusedLogged, and egress allowed again warns from scratch (fa6f180)
- 2026-10-21 R1.8 the exit predicate is MayEndAChain (Kind == NodeServer && AllowEgress); tested with a device whose section allows egress (fa6f180)
- 2026-10-21 R1.9 stale text: status.go calls DNSUpstreamsRefused an exit's in both places; TP-083's note names DataPlane.inWorker for the OS resolver configuration (fa6f180)
- 2026-10-21 R1.10 nits: the comment above the inWorker check in newResolver dropped; buildEditing takes the node whose section to edit and build calls it; dnsWorkerConfig's comment says the resolver has none to ask; the test renamed to TestAnUpstreamTheEgressRefusesIsNotAskedAndNamed; the shared egressBlocked was already only combined by slices.Concat (which copies) at the review point, nothing to change (fa6f180)
- 2026-10-21 mutation checks: the family sort disabled fails the uplink-family test; dropping the non-exit reset fails the loses-egress test; skipping egressMustStayClosed fails its test; the raw AllowEgress predicate fails the device case of the non-exit test
- 2026-10-21 the lab test's waitLog on the exit's no-upstream warning follows R1.6's wording; the first full lab run caught the stale regex (741c77b)
- 2026-10-21 make lint passes on the branch tip (the rewrite merge brought TP-116's go1.26.10, so vulncheck is green); make test passes (741c77b)
- 2026-10-21 make lab-test passes on 741c77b: the lab suite and all 35 packages' tests in lab nodes. An earlier run had TestTwoSpacesShareAListener fail once under the parallel load (no reply for a dialer); it passed alone and in the final run, and touches nothing this branch changed
- 2026-10-21 in-progress → review
- 2026-10-21 review → has-errors (round 2: R2.1–R2.9)
- 2026-10-21 has-errors → in-progress (round 2 findings)
- 2026-10-21 R2.1 EgressMustStayClosed is EgressNotWorthAllowing: the addresses the refusal hint never suggests opening; its comment, its test's comment and egressBlocked's comment (now pointing at it, the metadata hosts listed once) say nothing stops an operator from allowing one. Enforcement filed as TP-118 in backlog (ab1144b)
- 2026-10-21 R2.2 EgressNotWorthAllowing unmaps an IPv4-mapped address first, so the mapped form of a metadata address keeps the plain -dns-upstream hint; the test covers the mapped forms and 100.64.1.53 (widening the metadata host to 100.64.0.0/10 would fail it) (7e7ecad)
- 2026-10-21 R2.3 a test pins every range the check names inside egressBlocked (narrowing a blocked prefix fails it), and the agent's hint test covers the named metadata hosts — Azure's 168.63.129.16 and the mapped form — not only 169.254.169.254 (7e7ecad)
- 2026-10-21 R2.4 a later config's changed DNSUpstreams follow into the running resolver (dns.Server.SetUpstreams), a resolver started later getting the latest; a test through serveSpace drives two later configs; the order follows the uplink as of the last map applied — an uplink change alone re-runs nothing, no hook built, DESIGN.md says so (4343d9d)
- 2026-10-21 R2.5 apply reads the supervisor's egress once and passes it to both workerUpstreams and egressAttrs, so the defaults' order and the "map applied" line agree; tested with a supervisor whose snapshots differ per read (3c4361c)
- 2026-10-21 R2.6 a non-exit worker's resolver says it has no upstream at debug, not warned; the comment and TestServeSpace's worker subtest match (323281d)
- 2026-10-21 R2.7 DESIGN.md Upstreams: "the uplink's family first when it carries only one, as of the last map applied" (4343d9d)
- 2026-10-21 R2.8 buildEditing edited the swapped section and sent the sections unswapped: an edit of b's section reached a's recipient and b got a's unedited; it edits a pointer to the chosen section now, tested that b's edit reaches b alone (bc4fcf5)
- 2026-10-21 R2.9 nits: orderForUplink (a verb, always a copy); the stale parenthetical dropped from the every-upstream-refused test; the three exit setups share an exitSpaces helper (3c4361c, bc4fcf5)
- 2026-10-21 mutation checks: dropping a list entry fails the renamed test; dropping the Unmap fails its test; narrowing 100.64.0.0/10 fails the containment test; a second Egress read in apply fails the shared-snapshot test; warning unconditionally fails TestServeSpace; the old swap fails the buildEditing test; disabling the forwarding fails the later-configs subtest
- 2026-10-21 make lint and make test pass on 4343d9d; make lab-test passes on 4343d9d (the lab suite and all 35 packages in lab nodes). Not verifiable in-process: a query's path through the worker resolver's new upstreams — the resolver serves on overlay addresses no test process can bind; the change is observed through serveSpace's forwarding and the resolver's SetUpstreams
- 2026-10-21 in-progress → review
