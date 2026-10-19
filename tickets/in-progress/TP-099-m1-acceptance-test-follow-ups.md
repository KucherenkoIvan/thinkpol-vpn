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

## Review findings
- [ ] R5.1 lab/dns_test.go ~221 and the health closure ~129: `MustExec` inside lab.Eventually aborts instead of retrying; use Exec and return the error.
- [ ] R5.2 The server-exit test's doc (~162-167) claims the upstream queries leave through the worker's egress; since TP-098 nothing proves the resolver is the worker's. In the negative phase, assert the worker's own warning with its prefix, one regex on one line (`worker space=\S+ .*no upstream to ask: the worker's egress refuses`); match the parent's refusal line with one regex that pins the address (`refuses the upstream.*upstream=<ip>:5353`).
- [ ] R5.3 Rewrite the negative-control comment (~201-210), ~6 lines: the readiness probe asks the exit's resolver itself (a server with egress holds no overlay names, so NXDOMAIN aa means the tunnel and the resolver are up); a fresh direct name proves the device's own resolver is alive (not the tunnel); every name is asked once because answers are cached for 60 s; the positive control repeats the restart with the egress allowed.
- [ ] R5.4 A restartExit(egressAllowed netip.Prefix) closure replaces the two copied restart blocks (~211-216, ~230-235).
- [ ] R5.5 The positive control polls (mustResolve) for www4; the negative stays one-shot for www2.
- [ ] R5.6 Move tunnelNamesAskedOnlyOfTheExit to the end of the test so the domestic resolver's log covers www2 and www4 too.
- [ ] R5.7 lab/teardown_test.go: tunGone drops its unused *testing.T, says "the TUN is still there"; ipv6Guard's doc drops "the same shape as tunGone"; the file header is just "What a stop (or a disconnect) must take away."; guardState's doc starts with its name. One-shot calls get a longer exec timeout (like lab's execTimeout, 2 min) than the 10 s now used, or the 10 s is kept only for polls — say which.
- [ ] R5.8 A wantGuard(n, want) error helper next to ipv6Guard replaces the six read-and-compare copies in ipv6leak_test.go and localapi_test.go (make them consistently Fatalf for one-shots, Eventually for polls).
- [ ] R5.9 lab/localapi_test.go ~303-306: both families' tables hold unreachable routes whenever the route table is up (IPv4's unreachable 100.64.0.0/10, and 0.0.0.0/0 when the TUN is down; IPv6's ::/0): only the TUN's own default in each proves the routes came back. Say "routetable.Table" not "(routetable.go)". The doc at ~260-265 lists the TUN among what's gone.
- [ ] R5.10 noPing moves next to ping (lab/up_test.go) and takes a netip.Addr.
- [ ] R5.11 lab/labdns/main.go: one check "-server and -query go together" ((server == "") != (query == "")) at the top; delete the half-check in ask; doc: "prints the reply's rcode (with ` aa` when authoritative)", drop "that ignores the resolver flags". lab/README.md to match.
- [ ] R5.12 lab/dnscommon_test.go ~69-70: "The lab's addresses are private, which the worker's egress refuses unless egressAllowed covers them; the zero Prefix covers none."; mustAsk's error names both -server and -query.
- [ ] R5.13 DESIGN.md ~174: "Not yet on macOS: the per-call check sees only the groups the caller's process got at login (LOCAL_PEERCRED), so a member added since, whom the directory's gate lets through, is refused every call; see TP-094."
- [ ] R5.14 TP-085: the box stays record-only (what to capture and write down). Notes state what the agent checks afterwards: the direct name's query appears in the physical-interface capture (proving the capture saw DNS) and the tunnel-bound name's does not; that's R4's macOS DNS-leak evidence (PRD R4, DESIGN M1). Add DESIGN#milestones to refs. Append to its Log: "- 2026-10-19 docs (TP-099 rounds 3–5): the DNS-leak box records; Notes say what the agent checks".
- [ ] R5.15 tickets/done/TP-023-m1-acceptance.md ~57: the gap describing every tunnel-bound name failing on cloud exits is outdated since TP-098 (exits default to public resolvers); ~56: say exactly which members are refused (as R5.13). Append a TP-023 Log line "- 2026-10-19 docs (TP-099): the exit-DNS gap closed by TP-098; the macOS members gap worded as TP-094".
- [ ] R5.16 The acceptance box says `make lab-test LAB_P=1`: run it at the head and record the commit, or reword the box to the run actually recorded and say why.

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
- 2026-10-18 full suite at commit 30c8da8: `make lint`, `make test` pass; `make lab-test LAB_P=1 GOFLAGS=-p=4 THINKPOL_LAB_MAX_LABS=2` green (the lab package in 297 s, 34 in-node packages, no failures; other tickets' labs running throughout); the six changed tests rerun three times more (`go test -tags lab -count=1 -run 'TestUpRunsTheM0Space|TestDNSFollowsTheRules|TestDisconnectLeavesNothingBehind|TestLocalAPI|TestNoIPv6LeavesAroundTheTunnel|TestRouteTableSendsOnlyDirectAroundTheTunnel'`), all green
- 2026-10-18 in-progress → review (agent, TP-099 branch)
- 2026-10-19 review → in-progress (agent, TP-099 branch; round 4: review findings)
- 2026-10-19 owner approved DESIGN's reworded M1 done-when (round 3, 30c8da8)
- 2026-10-19 correction (round 4) to the round-3 item-4 line: TP-085's DNS-leak box was headed "recorded not judged" but still judged — it required that a direct name appear in the capture and no tunnel-bound one; round 4 rewords it to record both names and leave the judging to an agent
- 2026-10-19 items 1–3 (907ac1d): the server-exit negative control proves what TP-098 changed: the exit's log names the refused upstream, health counts `dns_upstream_refused` (read from `thinkpol status` on the server), the tunnel-bound name fails and the direct one still resolves; the positive control passes the same readiness probe (a ping and `mustAsk`'s authoritative NXDOMAIN) and one-shot resolves a fresh name (`www4.tunnel.test`), so the egress flag is the only difference between the two; the foreign resolver's log is read only once www4 is in it — the log is ordered, so no www2 there says it never saw the refused name; `upstreamNet` is computed once
- 2026-10-19 item 4 (907ac1d): `ipv6Guard` returns (guardState, error) and drops its unused *testing.T: absent only on nft's "No such file or directory", any other failure is an error, so polls retry it and one-shot checks fail with it; the ipv6leak poll's error names the state it got
- 2026-10-19 item 5 (907ac1d): `policyRules`, `routeTableRulesUp`, `routeTableRoutes`, `ipv6Guard`/`guardState` and `tunGone` live in one file, `lab/teardown_test.go` (package lab_test, the lab build tag): what a stop must take away
- 2026-10-19 items 6–8 (907ac1d): labdns refuses `-query` without `-server` at the top of main (the client ignores the resolver flags), and its doc and lab/README.md say it prints its rcode (with ` aa` when authoritative); `mustAsk`'s parameter is `resolver` and its exec error is checked before stdout; `startServerExit`'s comment says the zero Prefix passes no `-egress-allowed`, so the upstream is refused
- 2026-10-19 items 9–10 (907ac1d): the duplicate `noPing` after `tunGone` is dropped; the route-table comment reads "the route table's `unreachable ::/0` (routetable.go), there whenever it is up, is in the IPv6 table"
- 2026-10-19 items 11–12 (907ac1d, a60d2fc): TP-085's DNS-leak box records one direct and one tunnel-bound name with the capture (the Wi-Fi-change capture can be it), judging left to an agent, and its Log carries the round-4 line; DESIGN's local API macOS caveat names what is refused: group members whose membership the service can't see (TP-094)
- 2026-10-19 full suite at commit a60d2fc: `make lint`, `make test` pass; `make lab-test LAB_P=4 GOFLAGS=-p=4` green (the lab package in 225 s, 34 in-node packages, no failures); the six changed tests rerun twice more (`go test -tags lab -count=1 -run 'TestDNSFollowsTheRules|TestUpRunsTheM0Space|TestDisconnectLeavesNothingBehind|TestLocalAPI|TestNoIPv6LeavesAroundTheTunnel'`), all green
- 2026-10-19 in-progress → review (agent, TP-099 branch)
- 2026-10-19 note (round 4): items in the round-4 lines are the round-4 review's findings, not Scope items
- 2026-10-19 review → has-errors (agent, TP-099 branch; round 5: review findings R5.1–R5.16)
- 2026-10-19 has-errors → in-progress (agent, TP-099 branch; round 5)
