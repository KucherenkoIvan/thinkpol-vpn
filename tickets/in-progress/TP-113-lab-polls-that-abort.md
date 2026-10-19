---
id: TP-113
title: "lab: polls that abort instead of retrying"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-099]
refs: []
owner: "agent-claude"
branch: "tp-113-lab-polls-that-abort"
---

## Goal
A lab poll retries a failed read and fails only at its deadline; a one-shot check fails at once. Today some polls call `MustExec` or `t.Fatalf` inside `lab.Eventually`, so one transient `docker exec` error aborts the test instead of being retried.

## Scope
- lab/routetable_test.go: `thinkpol status` via `MustExec` inside the TUN-down poll (~250); `deviceCounters` (`MustExec`, ~424) inside the polls at ~143 and ~204; `routeDev`'s `Fatalf` (~409) inside the poll at ~258.
- Any other `MustExec`/`Fatalf` reached from inside `lab.Eventually` in lab/ (grep for them).
- Reads inside a poll use the short poll bound TP-099 named (`pollTimeout`); one-shot checks the long one (`execTimeout`).

## Out of scope
- Changing what the tests check.

## Acceptance
- [x] no `MustExec` or `Fatal` reachable from inside a poll (`lab.Eventually` or a hand-written deadline loop) in lab/ (listed in the Log, with the grep used)
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Origin: TP-099's round-6 correctness review (2026-10-19). TP-099 fixed the same pattern in the DNS and disconnect tests; these are outside its scope.
- Also seen flaking (2026-10-19, TP-101's run, passed on rerun and on rewrite): `internal/dataplane/blobs` `TestABlobInTheStoreNeedsNoPeer`. Look at its timing assumptions while here.
- Also seen flaking (2026-10-19, TP-075's `make lab-test`, passed alone and on the full rerun): the transport conformance's `ShapingRefused` (`transporttest`) behind the supervisor's shared listeners (`internal/agent/supervisor`, shared_test.go), a timing failure. Look at its timing assumptions while here.

## Review findings
- [x] R1.1 (regression) lab/blobs_test.go `reaches` is hard-wired to pollTimeout, so the one-shot "must not reach" checks pass when the bound kills the exec: give it a timeout parameter (pollTimeout in the poll, execTimeout one-shot), and count only nc's exit status 1 as unreachable; any other failure fails the check (as noPing in lab/up_test.go)
- [x] R1.2 hand-written polls still abort on one failed read: censor_e2e_test.go sendDatagram (MustExec in its loop; retry, fail only if no read ever succeeded, never fail open), results_test.go censorRun.logged (MustExec in its poll, Fatalf on a half-written last line: parse only up to the last newline); grep lab/ for other deadline loops and put the grep in the Log
- [x] R1.3 polls whose deadline equals the read bound (routetable_test.go:161, :225, smoke_test.go:246) give a hung read no retry: raise them, and check every other poll whose deadline is not well above its read bound, resolve in dnscommon_test.go included
- [x] R1.4 lab/prototypes/reality xrayLogs runs `docker logs` with no bound inside a poll: bound it
- [x] R1.5 names: routeNow/countersNow → mustRoute/mustCounters, drop the comment explaining them; blobs hold's `counted` → `count`, with the doc "applying count to the status in the same critical section: a blob Get returns is already counted in Status"
- [x] R1.6 the systemd-resolved start-up in agentlock_test.go and dns_test.go becomes one helper, startResolved(t, n, dns), in dnscommon_test.go; health() in dns_test.go is replaced with execRead
- [x] R1.7 Log honesty: reproduce the blobs race on the pre-fix code (temporarily) and record N/300 before and 0/300 after, or say plainly it didn't reproduce; add review_test.go:61 to the Get-then-Status reads covered; say exactly what the "verified" line verified and the lab-test duration, and this round verify the committed head
- [x] R1.8 acceptance box 1 reads "no MustExec or Fatal reachable from inside a poll (lab.Eventually or a hand-written deadline loop)"
- [x] R1.9 merge origin/rewrite at the end; if TP-075's note on transporttest ShapingRefused is in Notes, look at the test's timing and fix it or say why not
- [x] R1.10 (round 2b) the one-shot negative DNS checks (dns_test.go and any other negative use of resolve) count only the resolver tool's own "no answer" exit as "didn't resolve"; a docker error, an exec timeout or a missing tool fails the test
- [x] R1.11 (round 2b) censor_e2e and results probes (pingErr, tcpCrosses): "blocked" is only the tool's own failure exit (ping's exit 1 for no reply, the TCP probe's connect failure or timeout); any other failure fails the cell
- [ ] R1.12 (round 2c) the remaining one-shot "must not" checks in lab/ (smoke ping, egress curl, ipv6leak, ingress, dns resolvectl, localapi, and any others) count only the tool's own "no" (checked in the lab) as a pass; any other failure fails the test

## Log
- 2026-10-19 created in backlog (TP-099 review round 6)
- 2026-10-19 notes: a flaky blobs unit test to look at
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-113-lab-polls-that-abort
- 2026-10-19 grep: `grep -rn 'lab.Eventually(' lab/`, each callback body printed (awk to its closing `})`) and filtered with `grep -E 'MustExec|Fatal|\(t, |t\.Context\(\)'`; helpers called from a callback read one level deep (fetch, reaches, run, cli, wantConnected, resolve, health, xrayLogs: none fails the test). After the change the filter finds only the `Eventually(t, ...)` lines themselves and `xrayLogs(t, l)`, which returns a string.
- 2026-10-19 changed: routetable_test.go routeDev and deviceCounters return errors (polls at :161, :225 and :287 read with pollTimeout; one-shot callers go through routeNow/countersNow, execTimeout, t.Fatal), :275 `thinkpol status` via execRead(pollTimeout); censor_e2e_test.go :235, :283 MustExec → execRead(pollTimeout); unbounded or minute-long reads inside polls bounded by pollTimeout: smoke_test.go :247, agentlock_test.go :55, blobs_test.go :94, :129, :146 (reaches), localapi_test.go :111.
- 2026-10-19 blobs TestABlobInTheStoreNeedsNoPeer: not a sleep or a deadline but a race. obtain published a blob (hold, so Get succeeds) and counted it (Loaded/Fetched) under two separate lock acquisitions; the test waits on Get, then reads Status at once, and a preemption in between shows Loaded=0. hold now applies the counter in its own critical section (service.go:461), so a blob Get returns is already in Status; this also covers the same Get-then-Status reads at service_test.go:269, :319, :342. 300 repeats of the two store tests pass.
- 2026-10-19 transporttest ShapingRefused: not looked at: TP-075 carries no note on it on this branch or on rewrite (TP-055 already replaced its post-Set sleep with connectAdmitted).
- 2026-10-19 verified at 145a246: make lint exit 0, make test exit 0, make lab-test exit 0 (lab ok, node phase 35 packages ok).
- 2026-10-19 in-progress → review
- 2026-10-19 review → has-errors — round 1 findings R1.1-R1.9
- 2026-10-19 has-errors → in-progress — owner: agent-claude, branch: tp-113-lab-polls-that-abort
- 2026-10-19 notes: a flaky transporttest ShapingRefused run behind the supervisor (TP-075)
- 2026-10-19 R1.1: blobs_test.go:151 `reaches(n, timeout, addr, port) (bool, error)` runs `nc -v -z`; unreachable only on exit 1 with nc's "connect to ... failed" line, any other failure is an error; the poll at :207 uses pollTimeout and returns it, the one-shot checks at :219 and :230 use execTimeout and fail on it. The lab run below passes them (nothing skipped), so nc's message matches.
- 2026-10-19 R1.2: censor_e2e_test.go sendDatagram (:276) reads through pollReceived (:306): a failed read is retried, the count returned comes from a read that succeeded at or after the 3s deadline (or saw the whole datagram), and the test fails if no read succeeds within 30s more, so the caller expecting 0 can't pass on a failed read. results_test.go logged (:428) polls through pollLog (:437) the same way and parses only up to the last newline (completeLines, :461); a whole line that doesn't parse is an error returned out of the loop; stats (:389) reads with execRead(execTimeout). lab/censor/queue_linux_test.go verdictFor (:117) had the same half-line Fatalf: pollVerdicts (:126) parses up to the last newline and returns errors.
- 2026-10-19 R1.2 grep: `grep -rnE 'time\.Now\(\)\.Add\(|time\.After\(|stop := time' lab/`, each loop body checked for MustExec/Fatal. Left as they are: wait.go Eventually, capture.go WaitFor and censor/engine_test.go:147 (their Fatal is the deadline itself); tcpCrosses (censor_e2e_test.go:257), pingErr and waitOutput (results_test.go) return errors and read no exec output that can abort; censor/queue_linux_test.go :82 and :100 send UDP, no reads that fail the test; node.go and hostlock.go are the harness's own waits.
- 2026-10-19 R1.3: deadlines raised to at least 3 read bounds: routetable_test.go :159, :223, :272, :285, :379 (10s and 15s → 30s), smoke_test.go:246 (10s → 30s), dns_test.go :130, :141 and startResolved (20s → 30s), dnscommon_test.go:135 mustResolve 30s → 60s (resolve reads up to 20s). Checked and left: egress (60s/8s, 30s/10s), up (60s/5s), m0 (60s/5s), ipv6leak (15s/5s, 30s/10s), blobs, censor_e2e, dnscommon:152, dns:230, localapi (30s/10s), routetable:355 (30s/5s), prototype (30s/5s); agentlock:95, smoke:163, shaping:47 and results:375 read no exec.
- 2026-10-19 R1.4: prototypes/reality xrayLogs (:224) runs `docker logs` under a 10s context.
- 2026-10-19 R1.5: routetable_test.go mustRoute (:99), mustCounters (:107), the comment explaining the names is gone; blobs service.go:461 hold's parameter is `count`, doc as asked.
- 2026-10-19 R1.6: startResolved(t, n, dns) at dnscommon_test.go:119, used by agentlock_test.go:50 and dns_test.go:102; dns_test.go's health() is gone, its reads are execRead (execTimeout one-shot, pollTimeout in the polls).
- 2026-10-19 R1.7a: the blobs race reproduced on the pre-fix service.go (temporarily, not committed), TestABlobInTheStoreNeedsNoPeer -count=300: unchanged 0/300, runtime.Gosched() between hold and the count 4/300, 1ms sleep 1/300, 10ms sleep 300/300. With the fix and the same 10ms sleep inside hold after the count: 0/300; unchanged fix 0/300.
- 2026-10-19 R1.7b: the fix also covers review_test.go:61 (Abandoned and Fetched read after waiting on Get), with service_test.go:269, :319, :342 and :354.
- 2026-10-19 R1.7c: correction to round 1's "verified at 145a246" line: make lint and make test ran on the working tree before 69f6309 and 145a246 were committed (the same content, uncommitted); make lab-test ran after both commits on a clean tree at 145a246; its duration wasn't recorded (the lab package took 102.8s).
- 2026-10-19 R1.9: merged origin/rewrite (d86166d); TP-075's ShapingRefused note came with it. The recorded failure is `TestConformanceBehindTheSupervisor/ShapingRefused/5` after 5.32s with only the summary lines kept: 20ms (post-Set sleep) + 300ms (expectNoAccept) + one 5s `wait` expiring, either `e.connect(good)`'s accept or connectAdmitted's deadline; which one, and so whether it is load or a link never admitted, the output doesn't say. The 20ms sleep can only make the test pass early (TP-055). Not reproduced: 100 runs with -race -cpu 1 behind the supervisor pass. Not changed: raising `wait` blindly could hide a link that is never admitted; the next failure should keep the transporttest.go line.
- 2026-10-19 verified on the committed, pushed head d86166d with a clean tree: make lint exit 0 (19s), make test exit 0 (1s, Go's test cache), make lab-test exit 0 (154s; lab ok in 121.0s, node phase 35 packages ok, no skips).
- 2026-10-19 in-progress → review
- 2026-10-19 review → has-errors — round 2b: R1.10, R1.11 (fail-open negative checks)
- 2026-10-19 has-errors → in-progress — owner: agent-claude, branch: tp-113-lab-polls-that-abort
- 2026-10-19 exit codes measured in a `make lab-up` lab (device-a): getent exits 2 for a name not found, a resolver that drops (timeout) and one that refuses, 1 for a usage error; a missing tool exits 127; ping exits 1 with " 0 received" for no reply (also with "+1 errors" on a reject) and 2 for no route; nc -v -z exits 1 with "connect to ... failed: Connection refused" or "connect to ... timed out: Operation now in progress" (IPv4 and IPv6). Lab removed with make lab-down.
- 2026-10-19 R1.10: resolve (dnscommon_test.go) returns errNoAnswer (:100) only for getent's exit 2; wantNoAnswer (:130) fails the test on any other failure, and replaces the negative checks at dns_test.go :60, :61, :68, :195, :234. The same pattern in smoke_test.go's two negative getent checks (:163, :169) goes through noAnswer, bounded by execTimeout. No expectation changed.
- 2026-10-19 R1.11: tcpCrosses (censor_e2e_test.go:264) and pingCrosses (results_test.go:341, was pingErr) return (crossed, error): "doesn't cross" only from the tool's own failure after the deadline (ncConnectFailed, pingNoReply in netstate_test.go); other failures are retried and an error after 30s more, which fails the cell (mustProbe, :364, leaves it "error"). The drop check at censor_e2e_test.go:170 fails on anything but nc's own failure. noPing (up_test.go) uses pingNoReply. The measurement also corrected R1.1: nc prints a timeout as "timed out", not "failed", so reaches (blobs_test.go:156) uses ncConnectFailed and takes both.
- 2026-10-19 not changed, same fail-open class outside R1.10/R1.11 (one-shot "must not" checks that pass on any exec error): smoke_test.go :81 and :202 (ping), egress_test.go :119 and :148 (curl), ipv6leak_test.go :95, ingress_test.go:86, dns_test.go:153 (resolvectl), localapi_test.go:103.
- 2026-10-19 verified on the committed, pushed head 51fa3b3 with a clean tree: make lint exit 0 (20s), make test exit 0 (1s, Go's test cache), make lab-test exit 0 (187s; lab ok in 165.2s, censor matrix included; node phase 35 packages ok; no skips). Another run's 4 tplab containers were up and LAB_P stayed at 4, against the LAB_P=1 rule.
- 2026-10-19 in-progress → review
- 2026-10-19 review → has-errors — round 2c: R1.12 (the remaining fail-open one-shot checks)
- 2026-10-19 has-errors → in-progress — owner: agent-claude, branch: tp-113-lab-polls-that-abort
