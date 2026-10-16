---
id: TP-023
title: "M1 acceptance"
milestone: M1
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-013, TP-014, TP-017, TP-019, TP-020, TP-021, TP-022, TP-078, TP-079, TP-092]
refs: [N3, N8, R1, R2, R3, R4, R9, D1, D6, D8, DESIGN#milestones]
needs_human: macos
owner: glm-tp023
branch: tp-023-m1-acceptance
---

## Goal
M1's "done when" as lab tests, plus one real-world run on macOS.

## Scope
- Lab: browse the `internet` target through an egress node; `direct` vs tunneled destinations; DNS leak test; IPv6 leak test; overlay names; CLI connect/disconnect; teardown leaves nothing.
- The macOS checklists from TP-019 and TP-078 run once by the author on a real network.

## Out of scope
- The guard's leak paths on native IPv6 on macOS: the device run is TP-096 (the owner has no network with native IPv6).
- Confinement after a crash on macOS (the kill switch): TP-048.
- TP-019's leftover device steps: step 13 is TP-094; step 8's captures and step 15b are TP-085's device acceptance.

## Acceptance
- [x] lab tests green; they cover Linux leak guarantees (DNS, IPv6, the route table) and match DESIGN M1
- [x] macOS checklist results recorded in Notes; M1's claim for macOS is exactly what the device records show (the data plane TP-019; the guard loads, TP-078/TP-092), worded so nobody reads it as "macOS is safe"

## Notes

### Traceability

Every M1 claim, the test that proves it, and where. Tests that need the lab are behind the `lab` build tag; in-node tests guard on `THINKPOL_LAB`.

| Claim | Proving tests | Platform |
|---|---|---|
| Exit node with NAT (R1): internet traffic forwarded over IPv4 and IPv6, the internet sees only the exit's own addresses; egress off forwards nothing while the overlay relays | `lab/egress_test.go` `TestEgressThroughAnExit`; the masquerade itself: `internal/agent/supervisor/egress_linux_test.go` `TestEgress` | Linux lab |
| Route-table rules with GeoIP (R2): direct destinations leave in plaintext, foreign ones enter the TUN and never show on the physical side; the link bypasses the TUN; a gateway change re-applies; TunnelVision covered | `lab/routetable_test.go` `TestRouteTableSendsOnlyDirectAroundTheTunnel`; namespace enforcement, country-sized tables, hostile routes, gateways and bound sockets: `internal/dataplane/routetable/routetable_linux_test.go` `TestEnforcesInANamespace`, `TestCountrySizedTable`, `TestHostileLocalNetworkRoutes`, `TestGatewaysOnLinksAndBoundSockets` | Linux lab |
| Rule engine: actions `direct`/`chain`/`block`, matchers `default`/`local`/`cidr`/`geoip`, unknown actions and matchers fail closed (R2) | `internal/dataplane/rules/compile_test.go` `TestCompile`, `TestCompileMatchesFirstMatch`; `names_test.go` `TestNamesBlockUnknownActionsAndKeepUnknownMatchersFailClosed` | unit (pure Go) |
| Space-wide rules plus per-device overrides; presets "everything" and "all but domestic" (R3) | the engine's own-rules mechanism: `internal/dataplane/rules/compile_test.go` `TestEffectiveOverridesAndPresets`, `TestPresetRules`, `TestLocalFile`; what a device can do at M1: `TestRouteTableSendsOnlyDirectAroundTheTunnel` (preset switches) and `lab/localapi_test.go` `TestLocalAPI` (`rules preset`, stored and applied) | Linux lab + unit |
| DNS follows the rules; no DNS leaks (R4) | `lab/dns_test.go` `TestDNSFollowsTheRules` (resolv.conf and systemd-resolved; direct names to the domestic resolver only; tunnel-bound names only via the exit; blocked names fail; the domestic resolver is never asked a tunnel or overlay name); with the exit running as a server: `TestDNSFollowsTheRulesOnAServerExit` | Linux lab |
| Overlay names `<device>.<space>.internal` resolve (N3) | `TestDNSFollowsTheRules`: `device-b.lab.internal` over IPv4 and IPv6 via resolv.conf (device-a); via systemd-resolved (device-b) only device-a over IPv4 (`lab/dns_test.go`) | Linux lab; macOS device run 4, step 6 (tickets/done/TP-019) |
| Ingress/egress off by default; with ingress off its address never reaches devices; with both off the node only relays (N8) | the spec's defaults: `internal/devmap/spec_test.go` `TestSpecErrorsNameTheirLocation` (a device can't dial a server whose ingress is unset); `lab/ingress_test.go` `TestIngressOffAdmitsOnlyServers`; `TestEgressThroughAnExit` (final phase) | Linux lab |
| GeoIP lists distributed through the network, updatable without a release (R9): a tampered copy is rejected, the list fetched, kept, refetched; a list update keeps the previous list until its successor arrives | `lab/blobs_test.go` `TestBlobDistribution`; `internal/dataplane/routing_test.go` `TestRulesKeepThePreviousListUntilItsSuccessorArrives` | Linux lab + unit |
| No IPv6 leaks around the tunnel (D6): bound sockets confined, crash keeps the guard, the guard is restored when deleted, a clean stop removes it; IPv6-off overlay blocks too | `lab/ipv6leak_test.go` `TestNoIPv6LeavesAroundTheTunnel` (negative control included); `TestRouteTableSendsOnlyDirectAroundTheTunnel`'s IPv6-off parts | Linux lab; macOS: the guard loads, its leak paths are unproven (see macOS below) |
| macOS and Linux clients via CLI (D1, D8): status, connect, disconnect, logs, rules, permissions | `TestLocalAPI` (alice vs mallory, no secret in a status) | Linux lab; macOS: a member was refused (TP-094; whether it had logged in again isn't recorded) |
| Teardown leaves nothing: rules, routes, resolv.conf, resolved's config, the guard; after a CLI disconnect, resolv.conf (device-a's form of DNS), not resolved's | `TestRouteTableSendsOnlyDirectAroundTheTunnel` (`stopAndCheck`), `TestDNSFollowsTheRules` (resolv.conf restored after stop and crash), `TestNoIPv6LeavesAroundTheTunnel` (guard gone on clean stop); after a CLI disconnect: `TestDisconnectLeavesNothingBehind` | Linux lab; macOS: TP-019 manual session, "down leaves no routes", the kit's restore: CLEAN |

At M1 the per-device override a device can make is the preset choice (`rules preset`, stored in `rules.local`); the device's own rules aren't settable from the CLI or the local API (M4).

### Gaps

- **macOS on a network with native IPv6.** The device steps that would exercise the guard's leak paths on such a network (bound `ping6`/`curl -6 --interface`, tcpdump clean, still refused after `kill -9`) are parked in tickets/blocked/TP-096, blocked on the owner having no such network. Until then the guard's macOS behaviour rests on session B's clean health and the fake pfctl's tests (### macOS).
- **Known macOS limits** (TP-019's Notes, "Residual risks"): IPv4 from interface-bound sockets (TP-019's suspicion R2.8) is held back only by scoped routing: such sockets failed with "No route to host" in TP-019's device run 1, and did not bypass in run 4. There is no firewall backstop until TP-048, and the scoped host route to a direct DNS upstream is a known exception. After a crash, IPv4 follows the physical default until the agent restarts (TP-019, "Residual risks"). Foreign host routes over tunneled destinations are only counted; the roughly 200 ms TunnelVision window; DNS bypassed by encrypted-DNS profiles and iCloud Private Relay; DNS fails behind the Application Firewall until allowed, and again after every ad-hoc-signed update (TP-093); group members are refused by the local API on macOS (TP-094).
- **The exit's DNS on hosts whose resolvers are private or link-local** (most clouds, home LANs): every tunnel-bound name fails, failing closed (TP-098). The workaround is `-dns-upstream`; the owner approved public resolvers as the default there.
- **N8's "only relays" isn't lab-proven:** in `TestEgressThroughAnExit`'s final phase the both-off node is only ever a destination, never a relay for another node's traffic.
- **Resolved's config after a CLI disconnect isn't lab-proven:** the disconnect test's device (device-a) resolves through resolv.conf; systemd-resolved's state after `thinkpol disconnect` has no lab check.
- **R9 beyond GeoIP:** no lab test publishes a new list through a new map to a running device; geosite has no format (`internal/devmap/spec.go` refuses it in specs). List *contents* updating under a running device is unit-proven only (`TestRulesKeepThePreviousListUntilItsSuccessorArrives`).
- **TP-019's "next device run must check" items.** Run 4 recorded N1–N3, N5, N7–N10 and N12 as passed, and steps 14, 16, N2, N4 and N6 as INFO-only. N2 is INFO-only with no ticket; run 4 cites N12 while the list has 11 items.

### macOS

The M1 claim for macOS is exactly what the device records show, no more. The data plane — connect, rules, DNS and overlay names — works on a real Mac: TP-019's manual session and device runs (2026-10-15), cited by pointer only. The IPv6 guard: in TP-078's device session A it never came up (the guard's own check (saneRules) refused pfctl's re-ordered listing, fixed by TP-092); in session B it loaded and passed its own check (clean health) — but no device has seen it block anything. The Linux lab tests the nftables guard, which is different code; the pf guard's leak paths are tested only against the fake pfctl (`internal/dataplane/firewall/guard_darwin_test.go`, `fakepf_darwin_test.go`). **Nobody should read this as "macOS is safe"**: the guard's leak paths on native IPv6 — what it exists for — are parked in TP-096 (the owner has no network with native IPv6), and the kill switch is M2 (TP-048).

### Full suite

- 2026-10-16, commit f7c175c: `make lint` pass (0:24), `make test` pass (0:01), `make lab-test LAB_P=1 GOFLAGS=-p=4` pass (9:22): the `lab` package's tests in 216.4 s and all 34 packages' tests in lab nodes PASS; no flaky test, nothing rerun, no defect found. The new tests run twice more (`go test -tags lab -run 'TestDisconnectLeavesNothingBehind|TestDNSFollowsTheRulesOnAServerExit' ./lab`): both pass each time (9.99 s and 20.40 s; 10.98 s and 18.49 s). (Earlier suite entries were removed: their commit ids are stale after the history rewrite.)

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): acceptance scoped: leak guarantees are Linux-only until TP-019/TP-021
- 2026-10-15 decision (author, 2026-10-15): M1 is working core, not daily use; daily use waits for M2 disguised transport
- 2026-10-15 docs (backlog grooming): depends on TP-019 and TP-078; macOS required for M1 acceptance; TP-079 when merged
- 2026-10-15 docs (backlog grooming, review fixes): Scope checklists TP-078; acceptance wording restored
- 2026-10-15 docs: depends on TP-079 (merged)
- 2026-10-16 docs (TP-078 device session A): depends on TP-092
- 2026-10-16 backlog → in-progress, owner glm-tp023, branch tp-023-m1-acceptance
- 2026-10-16 Notes: traceability table, gaps, and the M1 claim for macOS (data plane TP-019, IPv6 guard TP-078/TP-092; not a claim that macOS is safe). The owner accepted the wording of that claim on 2026-10-16.
- 2026-10-16 full suite at commit 175f97d: lint/test/lab-test pass (Notes, Full suite). No new lab tests were needed: every Scope item already had a proving test.
- 2026-10-16 review → in-progress — round 2: review findings
- 2026-10-16 docs: the macOS M1 wording narrowed in PRD (M1 row, D6, R3, R9) and DESIGN (M1 done-when): leak guarantees are proven on Linux; on macOS M1 proves the data plane, DNS and that the guard loads. The owner accepted the earlier wording on 2026-10-16; this narrowing needs the owner's confirmation.
- 2026-10-16 review fixes (round 2): the macOS claim says what the device records show (session A: the guard never came up; session B: it loaded and passed its own check, no device has seen it block anything; the pf guard's leak paths are tested only against the fake pfctl); the IPv4/R2.8 sentence corrected (scoped routing only, the scoped direct-DNS-upstream host route a known exception, no backstop until TP-048, IPv4 after a crash); known macOS limits as one Gaps bullet; the D6, R3, N3, N8, R9 and D1/D8 rows corrected (spec defaults cited, "only relays" not lab-proven, geosite gap, list-update test cited, members refused TP-094, tray parity trivial); TP-019's carried-over device checks mapped to TP-094/TP-085/TP-093 with run 4's N-checks accounted for — no new carry-over ticket; traceability, Gaps and macOS under Notes as subsections, one copy of the macOS claim, lab timings moved here, Out of scope added, refs set.
- 2026-10-16 docs (TP-085): its device acceptance carries TP-019's step 8 captures and step 15b, in the record-don't-judge form.
- 2026-10-16 lab: `TestDNSFollowsTheRulesOnAServerExit` (R4 with the exit in server mode: the resolver in its worker, queries leaving through the namespace's egress — TP-020's follow-up) and `TestTeardownAfterCLIDisconnect` (after `thinkpol disconnect` the route table's rules and routes, resolv.conf and the IPv6 guard table are gone, and come back on connect) added.
- 2026-10-16 full suite at commit 293910c: lint/test/lab-test pass (Notes, Full suite). A first run of TestDNSFollowsTheRulesOnAServerExit failed: the server-mode exit needs `-egress-allowed` for its worker's upstream queries (the lab's addresses are private, which egress refuses); fixed in the test, no product change.
- 2026-10-16 the owner confirmed the narrowed M1 wording (PRD M1, D6, R3, R9; DESIGN M1)
- 2026-10-16 review → in-progress — round 3: review findings
- 2026-10-16 review fixes (round 3): PRD (M1 row, D6, R4) and DESIGN (M1 done-when, the pf anchor, the exit's DNS upstreams, the local API's macOS members) claim only what devices proved, no "verifies"; TP-085's refs gained R4 and D6, its device-acceptance box keeps only the checks, the carried-over TP-019 items moved to its Notes; lab: `TestTeardownAfterCLIDisconnect` renamed `TestDisconnectLeavesNothingBehind`, its `expect` closure became a `state` that returns errors for `lab.Eventually` (the TUN check included, no nested waits), the reconnect checks both families' 5301 rules, the guard's chain and AAAA resolution, with a leak capture; shared helpers `routeTableRoutes`/`hasGuard` (up_test.go) and the DNS lab's (`dnslab_test.go`: `startResolvers`, `buildDNSMap`, `osResolvConf`, `startServerExit`, `resolversAskedOnlyByTheExit`); `TestDNSFollowsTheRulesOnAServerExit` gained a negative control (the worker's egress closed to the upstream's subnet: a tunnel-bound name fails, a direct name still resolves); traceability rows R3, N8, permissions and teardown corrected, the R3 note moved under the table, Gaps gained TP-098, N8's "only relays", resolved's config after a CLI disconnect, and the N-item accounting (N2 INFO-only with no ticket; run 4 cites N12, the list has 11 items).
- 2026-10-16 in-progress → review — round 3 fixes done; make lint, make test, make lab-test LAB_P=1 green (Notes, Full suite)
