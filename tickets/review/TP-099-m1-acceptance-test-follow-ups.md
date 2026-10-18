---
id: TP-099
title: "M1 acceptance: test and doc follow-ups"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-023]
refs: [R4, D6, DESIGN#milestones, DESIGN#dns]
owner: claude-tp099
branch: tp-099-m1-acceptance-test-follow-ups
---

## Goal
The M1 lab tests check exactly what they claim, and the docs claim no more than the tests prove.

## Scope
Each item checked against the code before fixing.

1. `lab/dns_test.go` `TestDNSFollowsTheRulesOnAServerExit`, negative control (~:280): show the tunnel and the exit's resolver are reachable after the restart (e.g. ping the exit's overlay address) before treating the failed lookup of `www2.tunnel.test` as the worker's egress refusing it. Make "egress closed" a parameter of `startServerExit` instead of the inline copy, so the copy goes away.
2. `hasGuard` (`lab/up_test.go` ~:133): a single nft call whose failure means "absent", so a table vanishing mid-poll retries instead of `t.Fatalf`. Keep two meanings: "present" requires the chain, "absent" means no table by that name at all (an empty leftover table must fail the "gone" checks in `ipv6leak_test.go` and `localapi_test.go`).
3. `TestDisconnectLeavesNothingBehind` (`lab/localapi_test.go` ~:286-303): after reconnect, check IPv4 and IPv6 routes of the route table separately, e.g. require `default dev thinkpol0` in the `-4` table; the always-present `unreachable ::/0` must not satisfy both. Treat only "does not exist" from `ip link show` as "TUN gone". Either capture leaks after reconnect too, or make the ticket Log claim match.
4. `PRD.md` R4 (~:113): TP-019 run 4's macOS capture had no positive control (0 packets, `tickets/done/TP-019` ~:164), so it can't claim "no DNS leaks" on macOS. Reword it as consistent with no leak but unproven, or point the macOS part at TP-085. Resolve the contradiction with PRD's M1 row ("Leak guarantees are proven on Linux"). Note: the owner confirmed the M1 wording on 2026-10-16, and this changes it again, so the owner re-confirms the PRD wording before the ticket merges.
5. A `policyRules` helper next to `routeTableRoutes`, used at `routetable_test.go` and `localapi_test.go` (today two inconsistent copies).
6. DNS helper placement: shared `resolve`/`mustResolve`/`noLeaks` and `lab/dnslab_test.go` in one place, under a name that doesn't look like the `*_lab_test.go` convention.
7. `DESIGN.md`: the TP-098 caveat (~:144) names the worker's egress (not "isolation") in the "Not yet: …; see TP-098." pattern; the same pattern at ~:173 (TP-094); drop the device-history aside at ~:157. The macOS/TP-096 claim is stated once (DESIGN Milestones); PRD's M1 row points there.
8. Nits: the R4 row of TP-023's traceability table names macOS evidence consistently with item 4; rename the `state` closure (e.g. `wantConnected`); delete duplicate comments (`localapi_test.go` ~:259-264 vs ~:286-288; `dns_test.go` ~:232-239 vs ~:273-276; ~:250-251); rename `resolversAskedOnlyByTheExit` to say what it checks; assert `domesticAAAA` on a direct name.

## Out of scope
Product behaviour changes beyond what the tests and docs need to align.

## Acceptance
- [x] scope item 1: fixed or answered in the Log with a reason
- [x] scope item 2: fixed or answered in the Log with a reason
- [x] scope item 3: fixed or answered in the Log with a reason
- [ ] scope item 4: fixed or answered in the Log with a reason; owner re-confirmed PRD wording before merge
- [x] scope item 5: fixed or answered in the Log with a reason
- [x] scope item 6: fixed or answered in the Log with a reason
- [x] scope item 7: fixed or answered in the Log with a reason
- [x] scope item 8: fixed or answered in the Log with a reason
- [x] `make lint`, `make test` and `make lab-test LAB_P=1` pass, recorded with the commit id

## Notes

Origin: TP-023 review round 3 (2026-10-17), split under the three-round cap.

## Log
- 2026-10-17 created in backlog (TP-023 round 3 findings)
- 2026-10-18 backlog → in-progress (agent, TP-099 branch)
- 2026-10-18 item 1 (b6ea4c2): the server-exit DNS negative control first pings the exit's overlay address and resolves `server-1.lab.internal` through the exit's resolver after the restart, so the failed lookup of `www2.tunnel.test` can only be the worker's egress refusing the upstream, not a broken exit; "egress closed" is now the `egressOpen` parameter of `startServerExit`, the inline copy is gone.
- 2026-10-18 item 2 (b6ea4c2): `hasGuard` makes one nft call whose failure means absent, so a table vanishing mid-poll retries instead of `t.Fatalf`; it returns `present` (the table holds its chain), `empty` (a leftover table) or `absent` (no table by that name). The gone checks in `ipv6leak_test.go` and `localapi_test.go` demand `absent`. Checked with a temporary uncommitted run: an empty `nft add table inet thinkpol-guard` after disconnect made `wantConnected(false)` fail with "the IPv6 guard: empty, want absent".
- 2026-10-18 item 3 (b6ea4c2): `TestDisconnectLeavesNothingBehind` checks the route table's routes per family and requires the TUN's own `default dev thinkpol0` in each (the always-present `unreachable ::/0`, routetable.go's proto-86 IPv6 default, satisfies neither); only "does not exist" from `ip link show` counts as the TUN gone; leaks are captured after the reconnect too, so TP-023's round-3 Log claim now matches the test.
- 2026-10-18 item 4 (dccafe3): PRD R4's macOS column now reads "one device run's capture was consistent with no leak but proves none — it had no positive control, TP-019 run 4; the device evidence is to be recorded in TP-085"; the M1 row points the macOS leak-proof limits at DESIGN's milestones, which resolves the contradiction with "Leak guarantees are proven on Linux". R4 wording awaits the owner's re-confirmation.
- 2026-10-18 items 5, 6 (b6ea4c2): `policyRules` (both families, separate returns) sits next to `routeTableRoutes` (now per family too) and is used by `routetable_test.go` and `localapi_test.go`; `resolve`/`mustResolve`/`noLeaks` moved next to the DNS fixtures, whose file is `dnscommon_test.go` — package `lab_test`, not an inside-the-lab test as the `*_lab_test.go` names are.
- 2026-10-18 item 7 (dccafe3): DESIGN's macOS local API wording names what is missing ("not yet: membership as the file system sees it; see TP-094") instead of "members are refused until TP-094"; the pf anchor's device-history aside (the TP-092 device session) is dropped. The DNS "Upstreams" paragraph's TP-098 caveat (~:144) is left to TP-098. The macOS/TP-096 claim stays stated once in DESIGN Milestones; PRD's M1 row points there.
- 2026-10-18 item 8 (b6ea4c2): direct names assert AAAA answers (`domesticAAAA`) in all three DNS tests; `resolversAskedOnlyByTheExit` renamed `tunnelNamesAskedOnlyOfTheExit`; the `state` closure renamed `wantConnected`; duplicate comments deleted (the disconnect test's inline copy of its doc, the server-exit test's negative-control sentence and its "-mode device" aside). TP-023's traceability R4 row names the macOS evidence as PRD R4 now does.
- 2026-10-18 full suite at commit dccafe3: `make lint`, `make test` pass; the timed lab suite (`labctl down -stale`; `go test -tags lab -count=1 -v ./lab/...`; `labctl gotest -v -p 1 ./...`; `labctl down -tests`) exited 0 and 0 in 205 s + 333 s, 62 lab tests passed, none failed (one other ticket's lab was running throughout); the five changed tests rerun twice more, both green.
- 2026-10-18 in-progress → review (agent, TP-099 branch)
