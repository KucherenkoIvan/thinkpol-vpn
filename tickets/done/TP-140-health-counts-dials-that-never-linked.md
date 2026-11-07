---
id: TP-140
title: "Health counts the exits it dials: a dial that never linked is a problem"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
refs: [N2, docs/design/overlay.md#data-plane-every-node-one-binary]
owner: "agent-tp-140"
branch: "tp-140-health-counts-dials-that-never-linked"
---

## Goal
A device whose dialed exit never linked says so in its health, instead of `connected, health: ok`. A device with no DNS upstream to ask says so too. Lab and device verdicts, and later the kill switch, can then trust "health ok" to mean the tunnel is there.

## Scope
- Today `no_link_up` is raised only when `len(dp.Neighbors) > 0 && up == 0` (`internal/agent/status.go` ~425). `path.Node.Neighbors()` (`internal/dataplane/path/node.go` ~646–669) lists only neighbours that have a link; a pending dial (`n.dials`) without one isn't listed. So a dial that never succeeds leaves the list empty, and health stays ok.
- Count the dials: a node the device dials and has never linked to, past a deadline, raises a named problem (`no_link_up`, or a new code if the two cases should read differently; say which in Notes). Pick the deadline from what the path layer already has (the dial timeout, the 6 s dead interval) rather than a new constant.
- A missing DNS upstream ("DNS: no upstream to ask", `internal/agent/resolver.go` ~53–55, `internal/dataplane/dns/resolvconf.go` ~409) raises a named problem too, not only a log line.
- `thinkpol status` and `diag` show the new problems with the existing rendering; the problem list in the docs that name them is updated in the same branch.

## Out of scope
- Making `connect` wait for the first link: a separate question (the 2026-10-24 device run's reconnect returned `health: down: no_link_up` before the link came up 2 s later, which is the honest answer).
- Redialing on a network change: TP-085.

## Acceptance
- [x] a unit test: a dial with no link past the deadline raises the problem; before the deadline it doesn't; a link that comes up clears it
- [x] a unit test: no DNS upstream raises its problem; one configured clears it
- [x] lab: a device whose only exit drops every packet reports the problem in `thinkpol status`, and `health` isn't ok
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, Agent): done before the M2 lanes (disguise, censor lab, kill switch) start. M2's job is links that censors break, so health that says ok with no link makes every lab verdict unreliable.
- **Device evidence (the 2026-10-24 macOS device run, the connect-on-boot reboot).** Wi-Fi had no link during that boot. The agent logged `dial failed … netcfg: no default route (IPv4)` and `DNS: no upstream to ask`, the peer showed `no path yet  no handshake  rx 0 B`, the exit saw no handshake, and `thinkpol status` said `connected, health: ok`.
- The same logic was in place before the consolidation phase, so this isn't a regression; it was never seen because the link always came up.
- TP-144's device re-run checks the fix on the Mac (the connect-on-boot reboot with no link).
- **TP-139 verdicts (TP-139 owner session, 2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** Problem codes are snake_case (F5). Reuse `no_link_up` where the case reads the same, add a code where it doesn't, and name it per the naming rules. F16's fourth item (`health: ok` with a peer at `no path yet`) is this ticket's.
- **Codes (implementation, 2026-11-07).** A dial with no link is reused as `no_link_up` (down; `neighbor_down`, degraded, when another neighbor is up): it reads the same, no adjacent node answers. Deadline: the path layer's `DeadAfter` (6 s), the interval after which an unproven link is closed. No DNS upstream is a new code, `dns_no_upstream` (degraded), device only; a worker's upstreams stay `dns_upstream_refused`.
- **Fix round 1 (2026-11-07).** A dialed node with no link is listed down after its first failed dial attempt or DeadAfter since the dial started, whichever comes first; a first dial still waiting for an answer keeps its grace, so `connect` right after a failed dial says `no_link_up`, not ok. `dns_no_upstream` now also covers an OS that names no DNS server (Linux resolv.conf or resolved's uplink naming none: the previous upstreams are still asked, TP-130's keep-and-warn, and `dns.ErrNoSystemUpstream` in the System's Problem says so), is read from the resolver itself (no copied count), and is not raised beside `dns_upstreams_stale`.
- **`health: ok` is not end-to-end.** Health grades a node's neighbors, its first hops. With device → entry → exit, the entry link up and the exit never answering, health is ok; the same for a direct exit whose link is proven but whose WireGuard handshake never completes. RR48's row says so; grading exits by their handshake is out of scope here (the orchestrator files it).

## Review findings
- [x] R1.1 (should-fix) a dial that already FAILED reads `health: ok` for up to DeadAfter (6 s), so `connect` prints `connected, health: ok` with the peer at `no path yet`: list a dialed node with no link as down after its first failed dial or after DeadAfter, whichever comes first (a dial still waiting for an answer keeps its grace); fake-clock test; path/doc.go says the deadline counts from the latest dial start (a map change of the node's endpoints restarts it)
- [x] R1.2 (should-fix) `directUpstreams` copies the resolver's upstream count in three places, not atomically with the resolver (a false `dns_no_upstream` or a false ok); drop the copy and read the count from the dns.Server at status time; test: no upstream, then one through setUpstreams (config reload), clears the problem
- [x] R1.3 (should-fix) a failed first read of the OS's resolvers raises both `dns_upstreams_stale` and `dns_no_upstream`: the upstreams are unknown, not absent; don't raise `dns_no_upstream` with `dns_upstreams_stale`; test row for the failed read
- [x] R1.4 (should-fix) Linux: a resolv.conf (or resolved uplink) naming no server keeps the previous upstreams (TP-130, stays) and only logs; health must also report `dns_no_upstream` while the OS names no server, and clear when it names one again; unit test on the Linux path
- [x] R1.5 (should-fix, docs) health ok is not end-to-end (entry up, exit never answering; a direct exit's link proven but its WireGuard handshake never completing): say so in Notes, RESIDUAL-RISKS.md and api-overview.md's F16 item 4 / TP-140 text
- [x] R1.6 (nits) status_test: a no_link_up before DeadAfter fails, the clearing assertion is never skipped, a two-exit variant (degraded + neighbor_down); lab/health_test: drop the healthOK checks that can't be true after `health: down` matched; api-overview.md: move TP-140 out of "Planned, not built" and update its rows; api-overview-reference.md: the code is neighbor_down when another neighbour is up; fix the Log line that swaps the two lab subtests

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run and code-health review: before-M2 list)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Agent)
- 2026-11-07 TP-139 verdicts noted
- 2026-11-07 backlog → in-progress, owner: agent-tp-140
- 2026-11-07 done (2129a23): path.Node.Neighbors lists a node dialed for DeadAfter with no link as down (dialLoop.started), so health raises no_link_up/neighbor_down; health dns_no_upstream from runner.directUpstreams; docs: path doc.go, routing.md, api-overview.md, api-overview-reference.md
- 2026-11-07 tests: path TestNeighborsListADialThatNeverLinkedPastDeadAfter, agent TestADialThatNeverLinkedIsNoLinkUp, TestNoDirectUpstreamIsAProblem, TestAConfiguredUpstreamIsNoProblem, lab TestHealthWithNoLinkUp (packet drop, every dial fails)
- 2026-11-07 mutations, each failed its test: Neighbors deadline dropped (listed before DeadAfter: path + agent tests), never-linked dial never listed (path + agent tests, and lab "every dial fails" timed out on no_link_up), health ignores DNSNoUpstream, OS-told upstreams not counted, configured upstreams not counted
- 2026-11-07 the lab "every dial fails" subtest is the regression guard: the udp transport's Dial only opens a socket (no handshake), so a server that drops every packet still gives an unproven link, listed down, and that case raised no_link_up before this branch (read from the code, not re-run without the fix)
- 2026-11-07 merged origin/rewrite (TP-130); make lint, make test green; lab TestHealthWithNoLinkUp passed
- 2026-11-07 not verifiable here: the macOS connect-on-boot case (TP-144's device re-run); lab devices read `nameserver 127.0.0.1` as an upstream, so dns_no_upstream is unit-tested only
- 2026-11-07 make lab-test green on e0b30da (lab, lab/censor, lab/ip, lab/prototypes/reality ok; 36 packages in a lab node ok); an earlier full run was cut off by a session time limit, not by a failure
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.1–R1.6)
- 2026-11-07 has-errors → in-progress, owner: agent-tp-140 (fix round 1)
- 2026-11-07 R1.1: path dialLoop.failed (set on a failed attempt); Neighbors lists a never-linked dial once failed or DeadAfter since its start; doc.go says the deadline counts from the latest dial start. Tests: path TestNeighborsListAFailedDialAtOnce (fake clock never moved), TestNeighborsListAnUnansweredDialPastDeadAfter (a dial held unanswered keeps its grace); agent TestADialThatFailedIsNoLinkUp (DeadAfter 1 min, no_link_up at once, clears when the exit starts, no skip), TestADialThatFailedBesideALinkIsNeighborDown (two exits: degraded, neighbor_down)
- 2026-11-07 R1.6 status_test: the old "no_link_up before DeadAfter fails" assertion is superseded by R1.1 (a refused dial is listed at once by design); the grace before DeadAfter is asserted in the path test with the fake clock instead
- 2026-11-07 R1.2: directUpstreams dropped; noUpstream reads dns.Server.HasUpstreams at status time. Test TestALaterConfigsUpstreamClearsNoUpstream (none, then setUpstreams)
- 2026-11-07 R1.3: DNSNoUpstream isn't set while DNSUpstreamsStale. Test TestAFailedFirstReadIsStaleNotNoUpstream (stale only; the first good read naming none is dns_no_upstream)
- 2026-11-07 R1.4: resolvConf.noServer from each good read; Problem adds dns.ErrNoSystemUpstream (not unprotected) while the OS names none, previous upstreams still asked (TP-130 kept); status raises dns_no_upstream from it. Tests: dns TestResolvConfARewriteNamingNoServerIsNoSystemUpstream, Unprotected row, TestResolvConfAnOwedReadThatNamesNoServerKeepsTheUpstreams and TestResolvConfAFailedFirstReadThenEmptyTellsAnEmptyAnswer now expect it; agent TestTheOSNamingNoServerIsNoUpstream
- 2026-11-07 R1.5: Notes, RR48's row extended (health ok with the first hop up while the exit never handshakes), api-overview.md TP-140 and F16; R1.6 docs: TP-140 moved to "Built since the snapshot", reference names neighbor_down; lab/health_test.go healthOK checks after a matched `health: down` dropped
- 2026-11-07 R1.6 Log line swap: re-read the earlier lines against lab/health_test.go and found none swapped ("every dial fails" is the regression guard; "drops every packet" gave an unproven link, listed down, before this branch); earlier lines left as written
- 2026-11-07 mutations, each failed its test: Neighbors ignores failed (path TestNeighborsListAFailedDialAtOnce, agent TestADialThatFailedIsNoLinkUp); a pending dial always listed (TestNeighborsListAnUnansweredDialPastDeadAfter); a never-linked dial never listed (TestADialThatFailedBesideALinkIsNeighborDown); noUpstream snapshots the count at creation (TestALaterConfigsUpstreamClearsNoUpstream); stale not suppressing (TestAFailedFirstReadIsStaleNotNoUpstream); status ignores ErrNoSystemUpstream (TestTheOSNamingNoServerIsNoUpstream); noServer never set, and never cleared (TestResolvConfARewriteNamingNoServerIsNoSystemUpstream); Unprotected counts ErrNoSystemUpstream (TestUnprotectedSortsProblems)
- 2026-11-07 make lint, make test green
- 2026-11-07 make lab-test green on ad9fd88 (lab, lab/censor, lab/ip, lab/labctl, lab/prototypes/reality ok; 37 packages in a lab node ok)
- 2026-11-07 not verifiable here: the macOS connect right after a failed dial (TP-144's device re-run); dns_no_upstream from a real resolv.conf or resolved uplink naming none is unit-tested only (lab devices read `nameserver 127.0.0.1`)
- 2026-11-07 in-progress → review
- 2026-11-07 review → done, merged into rewrite (round 1: go-paranoid, go-style, pocket-torvalds, same-family second Opus; R1.1–R1.6 fixed; delta check: merge)
