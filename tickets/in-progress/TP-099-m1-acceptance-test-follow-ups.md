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
- [ ] scope item 1: fixed or answered in the Log with a reason
- [ ] scope item 2: fixed or answered in the Log with a reason
- [ ] scope item 3: fixed or answered in the Log with a reason
- [ ] scope item 4: fixed or answered in the Log with a reason; owner re-confirmed PRD wording before merge
- [ ] scope item 5: fixed or answered in the Log with a reason
- [ ] scope item 6: fixed or answered in the Log with a reason
- [ ] scope item 7: fixed or answered in the Log with a reason
- [ ] scope item 8: fixed or answered in the Log with a reason
- [ ] `make lint`, `make test` and `make lab-test LAB_P=1` pass, recorded with the commit id

## Notes

Origin: TP-023 review round 3 (2026-10-17), split under the three-round cap.

## Log
- 2026-10-17 created in backlog (TP-023 round 3 findings)
- 2026-10-18 backlog → in-progress (agent, TP-099 branch)
