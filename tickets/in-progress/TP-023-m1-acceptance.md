---
id: TP-023
title: "M1 acceptance"
milestone: M1
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-013, TP-014, TP-017, TP-019, TP-020, TP-021, TP-022, TP-078, TP-079, TP-092]
refs: [DESIGN#milestones]
needs_human: macos
owner: glm-tp023
branch: tp-023-m1-acceptance
---

## Goal
M1's "done when" as lab tests, plus one real-world run on macOS.

## Scope
- Lab: browse the `internet` target through an egress node; `direct` vs tunneled destinations; DNS leak test; IPv6 leak test; overlay names; CLI connect/disconnect; teardown leaves nothing.
- The macOS checklists from TP-019 and TP-078 run once by the author on a real network.

## Acceptance
- [x] lab tests green; they cover Linux leak guarantees (DNS, IPv6, the route table) and match DESIGN M1
- [x] macOS checklist results recorded in Notes; M1's claim for macOS is exactly what the checklist shows (data plane TP-019, IPv6 guard TP-078), worded so nobody reads it as "macOS is safe" (independent design review, 2026-10-13)

## Notes
- **Scope of the leak guarantees (TP-062), superseded 2026-10-15:** M1 needs a real Mac; TP-019 and TP-078 are in `depends_on`. The Linux-only acceptance fallback no longer applies.
- **M1 claim (author, 2026-10-15):** M1 proves the core works on a real Mac and on Linux. It does not claim daily use. Daily use is success metric 2, and it starts after M2's disguised transport.

## Traceability

Every M1 claim, the test that proves it, and where. Tests that need the lab are behind the `lab` build tag; in-node tests guard on `THINKPOL_LAB`.

| Claim | Proving tests | Platform |
|---|---|---|
| Exit node with NAT (R1): internet traffic forwarded over IPv4 and IPv6, the internet sees only the exit's own addresses; egress off forwards nothing while the overlay relays | `lab/egress_test.go` `TestEgressThroughAnExit`; the masquerade itself: `internal/agent/supervisor/egress_linux_test.go` `TestEgress` | Linux lab |
| Route-table rules with GeoIP (R2): direct destinations leave in plaintext, foreign ones enter the TUN and never show on the physical side; the link bypasses the TUN; a gateway change re-applies; TunnelVision covered | `lab/routetable_test.go` `TestRouteTableSendsOnlyDirectAroundTheTunnel`; namespace enforcement, country-sized tables, hostile routes, gateways and bound sockets: `internal/dataplane/routetable/routetable_linux_test.go` `TestEnforcesInANamespace`, `TestCountrySizedTable`, `TestHostileLocalNetworkRoutes`, `TestGatewaysOnLinksAndBoundSockets` | Linux lab |
| Rule engine: actions `direct`/`chain`/`block`, matchers `default`/`local`/`cidr`/`geoip`, unknown actions and matchers fail closed (R2) | `internal/dataplane/rules/compile_test.go` `TestCompile`, `TestCompileMatchesFirstMatch`; `names_test.go` `TestNamesBlockUnknownActionsAndKeepUnknownMatchersFailClosed` | unit (pure Go) |
| Space-wide rules plus per-device overrides; presets "everything" and "all but domestic" (R3) | `internal/dataplane/rules/compile_test.go` `TestEffectiveOverridesAndPresets`, `TestPresetRules`, `TestLocalFile`; on a running device: `TestRouteTableSendsOnlyDirectAroundTheTunnel` and `lab/localapi_test.go` `TestLocalAPI` (`rules preset`, stored and applied) | Linux lab + unit |
| DNS follows the rules; no DNS leaks (R4) | `lab/dns_test.go` `TestDNSFollowsTheRules` (resolv.conf and systemd-resolved; direct names to the domestic resolver only; tunnel-bound names only via the exit; blocked names fail; the domestic resolver is never asked a tunnel or overlay name) | Linux lab |
| Overlay names `<device>.<space>.internal` resolve (N3) | `TestDNSFollowsTheRules` (`device-b.lab.internal`, IPv4 and IPv6, via resolv.conf and resolved) | Linux lab; macOS device run 4, step 6 (tickets/done/TP-019) |
| Ingress/egress off by default; with both off the node only relays (N8); with ingress off its address never reaches devices | `lab/ingress_test.go` `TestIngressOffAdmitsOnlyServers`; `TestEgressThroughAnExit`'s final phase (ingress=off egress=off) | Linux lab |
| GeoIP lists distributed through the network, updatable without a release (R9): a tampered copy is rejected, the list fetched, kept, refetched | `lab/blobs_test.go` `TestBlobDistribution` | Linux lab |
| No IPv6 leaks around the tunnel (D6): bound sockets confined, crash keeps the guard, the guard is restored when deleted, a clean stop removes it; IPv6-off overlay blocks too | `lab/ipv6leak_test.go` `TestNoIPv6LeavesAroundTheTunnel` (negative control included); `TestRouteTableSendsOnlyDirectAroundTheTunnel`'s IPv6-off parts | Linux lab; macOS: the guard loads and is enforced (TP-078 device sessions A and B), leak paths on native IPv6 not proven — gap below |
| macOS and Linux clients via CLI (D1, D8): status, connect, disconnect, logs, rules, permissions | `TestLocalAPI` (alice vs mallory, no secret in a status) | Linux lab; macOS: TP-019 manual session and device runs (`up`, `status`, `down`) |
| Teardown leaves nothing: rules, routes, resolv.conf, resolved's config, the guard | `TestRouteTableSendsOnlyDirectAroundTheTunnel` (`stopAndCheck`), `TestDNSFollowsTheRules` (resolv.conf restored after stop and crash), `TestNoIPv6LeavesAroundTheTunnel` (guard gone on clean stop) | Linux lab; macOS: TP-019 manual session, "down leaves no routes", the kit's restore: CLEAN |

### Gaps

- **macOS on a network with native IPv6.** The device steps that would exercise the guard's leak paths on such a network (bound `ping6`/`curl -6 --interface`, tcpdump clean, still refused after `kill -9`) are parked in tickets/blocked/TP-096, blocked on the owner having no such network. Until then the guard's macOS behaviour rests on the Linux guard's lab tests (`internal/dataplane/firewall/guard_linux_test.go`) and the fake pfctl's tests.
- **TP-019's carried-over device checks.** Checklist steps 13 and 15b are ticketed (TP-094, TP-093); step 8's captures and the round-5 "next device run must check" items 1–11 are ticketed nowhere. Proposed ticket: "macOS device-run checks carried over from TP-019" (needs a device run; the checks are already written down in tickets/done/TP-019).

## macOS

The M1 claim for macOS is exactly what the device records show, no more. The data plane — connect, rules, DNS and overlay names — and the IPv6 guard's load and enforcement work on a real Mac: TP-019's manual session and device runs (2026-10-15), TP-078's and TP-092's device sessions (2026-10-16), cited by pointer only. **Nobody should read this as "macOS is safe"** (independent design review, 2026-10-13): the guard's behaviour on a network with native IPv6 — the leak paths it exists for — is proven only in the Linux lab and against the fake pfctl, with the device steps parked in TP-096 (the owner has no network with native IPv6). And the kill switch is M2 (TP-048), so IPv4 from interface-bound sockets is not confined on macOS yet (TP-019's suspicion R2.8 stays open until then).

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
- 2026-10-16 review → in-progress — round 2: review findings
- 2026-10-16 full suite at commit 175f97d: `make lint` pass (1:42), `make test` pass (1:04), `make lab-test LAB_P=1 GOFLAGS=-p=4` pass (9:23): the `lab` package's tests in 210.9 s and all 34 packages' tests in lab nodes PASS; no flaky test, nothing rerun, no defect found. No new lab tests were needed: every Scope item already has a proving test (Notes, Traceability). Nothing could not be verified on this branch except what the tickets already park: TP-096's native-IPv6 device steps and TP-019's leftover device checks.
