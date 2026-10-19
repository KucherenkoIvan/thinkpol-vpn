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
- [x] scope item 4: fixed or answered in the Log with a reason; owner re-confirmed PRD wording before merge
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
- 2026-10-18 review → in-progress (agent, TP-099 branch; round 2: review findings)
- 2026-10-18 round 2, items 1–5 and 7: item 1 corrected below (the readiness check is `mustAsk`, `labdns`'s client mode, and the foreign resolver's log is asserted); item 2 `hasGuard` renamed `ipv6Guard`, each state's meaning stated once, the ipv6leak messages print the state got; item 3 the `unreachable ::/0` comment names the route table, not the guard; item 4 one `tunGone` helper (only "does not exist" from `ip link show` counts) for `TestLocalAPI` and `TestDisconnectLeavesNothingBehind`; item 5 the direct lookup after the restart uses `www3.direct.test`, never asked before (the resolver caches answers with a 60 s TTL); item 7 nits: the dnscommon file comment deleted, `mustResolve` documented, the needless `other` dropped, `startServerExit` takes the egress-allowed `netip.Prefix`, the negative control's comments folded, a `startDeviceExit` helper, `routetable_test.go`'s crash checks use `policyRules` for both families, the item-4 Log line no longer quotes the PRD cell. (Round-2 finding itself: the exit's resolver answers no overlay names — server with egress holds none — so the readiness probe is its authoritative NXDOMAIN, found on the first full lab run, e50404b.)
- 2026-10-18 docs (item 6, 21ff8ec): PRD R4's macOS column reads "M1 (Linux lab; macOS: no DNS leak proven yet, TP-085)"; PRD's M1 row points the macOS limits at DESIGN's milestones instead of restating them; DESIGN's M1 done-when names both unproven on macOS — the guard's leak paths (TP-096) and DNS leaks (TP-085); the local API's macOS caveat is in DESIGN's "not yet …" pattern; DESIGN's TP-098 caveat paragraph (~:144) is left alone: TP-098 rewrites it; TP-023's traceability R4 row keeps the run-4 detail (steps 6, 12 and 16 zero-packet captures, no positive control) with a Log line; TP-085 gained the acceptance box "a DNS-leak capture on the physical interface with a positive control: a direct name appears in it, and no tunnel-bound name does". Acceptance box 4 stays unchecked: the owner re-confirms the PRD wording before merge.
- 2026-10-18 full suite at commit 2c89eac: `make lint`, `make test` pass; `make lab-test LAB_P=1 GOFLAGS=-p=4` green (the lab package in 246 s, 34 in-node packages, no failures; one other ticket's lab was running throughout); the changed tests rerun twice more with `go test -tags lab -count=1 -run '<names>'`, both green.
- 2026-10-18 in-progress → review (agent, TP-099 branch)
- 2026-10-18 owner re-confirmed the PRD wording (R4 cell, M1 row) and DESIGN M1 done-when as of 21ff8ec
- 2026-10-18 review → in-progress (agent, TP-099 branch; round 3: review findings)
- 2026-10-18 item 1 (round 2 correction): the readiness probe in the round-1 line went through device-a's own resolver and never reached the exit; it is `mustAsk`, `labdns`'s client mode: asked at the exit's overlay address for an overlay name, the exit's resolver answers itself with an authoritative NXDOMAIN (a server with egress holds no overlay names), and the foreign resolver's log is checked for never seeing the refused name; "egress closed" is the zero `netip.Prefix` of `startServerExit`, renamed `egressAllowed` in round 3
- 2026-10-18 item 4 (round 2 correction): PRD R4's macOS column reads "M1 (Linux lab; macOS: no DNS leak proven yet, TP-085)" instead of the round-1 wording; the run-4 detail stayed in TP-023's traceability table
- 2026-10-18 Log repair (round 3): the round-1 item lines, edited in place in round 2, are restored and the round-2 corrections appended, as the Log is append-only
- 2026-10-18 item 1 (round 3): the negative control gained a positive control — the same restart with the egress allowed, once more, resolving a fresh tunnel-bound name (`www4.tunnel.test`) — so the egress flag is the only difference between the two; `labdns`'s client mode prints only the reply's rcode (" aa" when authoritative), exits non-zero only without a reply and refuses an empty -query; `mustAsk` compares stdout with want and retries on an error
- 2026-10-18 item 2 (round 3): `ipv6Guard` reads absent only from nft's "No such file or directory"; any other failure is an unknown state carrying the reason (the shape of `tunGone`), so polls retry and the one-shot gone checks fail with it
- 2026-10-18 item 4 (round 3): TP-085's Notes carry R4's macOS DNS-leak capture (PRD R4, DESIGN M1), and its acceptance box is recorded-not-judged like its other device boxes
- 2026-10-18 item 7 (round 3): DESIGN's local API macOS caveat is its own sentence; the M1 done-when reads "Not yet proven on a device: that the guard blocks its leak paths (TP-096) and that DNS doesn't leak (TP-085)"
- 2026-10-18 item 8 (round 3): `routeTableRulesUp` beside `policyRules` replaces the three "5301:" checks; `startServerExit`'s parameter is `egressAllowed`; the reconnect leak check asks `www4.direct.test`, never asked before; the duplicate comment over `tunnelNamesAskedOnlyOfTheExit` is gone
- 2026-10-18 full suite at commit 30c8da8: `make lint`, `make test` pass; `make lab-test LAB_P=1 GOFLAGS=-p=4 THINKPOL_LAB_MAX_LABS=2` green (the lab package in 297 s, 34 in-node packages, no failures; other tickets' labs running throughout), finished 18:35 +05; the six changed tests rerun three times more (`go test -tags lab -count=1 -run 'TestUpRunsTheM0Space|TestDNSFollowsTheRules|TestDisconnectLeavesNothingBehind|TestLocalAPI|TestNoIPv6LeavesAroundTheTunnel|TestRouteTableSendsOnlyDirectAroundTheTunnel'`), all green
- 2026-10-18 in-progress → review (agent, TP-099 branch)
- 2026-10-19 review → in-progress (agent, TP-099 branch; round 4: review findings)
