---
id: TP-253
title: "Flaky transport/reality TestConformance/Delivery: 'unexpected ccs message'"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-253
branch: tp-253-reality-ccs-flake
---

## Goal
In TP-239's lab-test-default run (2026-11-19) the reality transport package's TestConformance/Delivery failed once with nginx (the camouflage site) reporting "unexpected ccs message"; a targeted re-run passed 3 of 3. Find what sends a ChangeCipherSpec the site doesn't expect (a TLS 1.3 middlebox-compat CCS at the wrong time, a fallback to the camouflage path mid-handshake, a retry reusing a connection) and fix the cause; if it's a real product behaviour a censor could see, say so plainly.

## Scope
- Reproduce, name what sends the ChangeCipherSpec the site doesn't expect, and fix the cause; say in Notes whether a censor could see it.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [x] 20 runs of the test under load pass, and a mutation that brings the cause back fails. The forced repro is the proof: COUNT=20 runs in one process, which reads the roots once, so the 20 runs show only that nothing else regressed.
- [x] No retries and no longer timeouts without a cause.

## Notes
**The failure wasn't the ChangeCipherSpec.** Both lab failures (TP-239's runs at 9632e30b and one before it) say the same thing: `TestConformance/Delivery (10.01s)` failed at `reality: target 127.0.0.1:… didn't complete a TLS handshake for every server name in 10s`. That is `detect` in Listen: REALITY's detection of the shared Go target's records didn't end within `detectWait`. nginx's three `unexpected ccs message` lines come from another test of the package (`TestAfterTheLabSitesFINTheSameWriteFails`, the only one that starts nginx) and appear in passing runs too: the full-lab logs of three other branches have the same three lines, and so does this branch's passing lab-gotest of the package.

**What sends the CCS nginx doesn't expect:** REALITY itself. Its detection of the target's records (`DetectPostHandshakeRecordsLens`, xtls/reality `record_detect.go`) opens, per server name and ALPN, a second connection (`CCSDetectConn`) that sends the target 2 extra ChangeCipherSpec records and, only if the target hasn't alerted within a second, 15, then 16, to learn how many the site tolerates (REALITY's server then tolerates as many on authenticated connections, `GlobalMaxCSSMsgCount`). OpenSSL refuses the first burst, so nginx gets only those 2 and logs one `[crit] … unexpected ccs message` per ALPN, three per server name. The detection runs once per server process for each (target, server name, ALPN) (REALITY's `LoadOrStore` on the key), again only when a Listen re-runs a stalled detection, or after a restart; handoff workers never run it; it isn't per Listen, isn't periodic, and no client or prober can trigger it. **A censor can use it:** the nginx line carries the client's address, which is the server's, so whoever runs (or can compel) the camouflage site learns the address of every REALITY server using it, timed to restarts (with RR32's shared target, one site's log is a census); a passive observer of the server's uplink sees the ChangeCipherSpec records in the clear and the detection's Go-fingerprinted ClientHellos. Stock REALITY and Xray do the same, so it marks a REALITY server, not thinkpol in particular. Now its own row, RR66 (RR31 points to it), documented in the package doc. Whether thinkpol can avoid it without patching REALITY is open: it might pre-store the records from a detection of its own, without the probe (it already wraps `GlobalPostHandshakeRecordsLens`, and REALITY reads `GlobalMaxCSSMsgCount` only if set); reviewers disagree, so it is TP-256 (design note first). TP-257: handoff workers never get `GlobalMaxCSSMsgCount`, so they may tolerate a different number of those records than the main listener.

**Root cause of the flake.** REALITY's detection verifies the target with utls against the system roots (its Config has no RootCAs). crypto/x509 reads the system roots from disk once per process, on first use: on the lab image (Debian, ca-certificates) that is the bundle plus each certificate file in `/etc/ssl/certs`, on the overlay filesystem of a lab node under a loaded disk, with no bound. With `TrustTargetRoots` (every test and the lab), `verifyTarget` doesn't touch the system roots, so the package's first Listen (TestConformance/Delivery, the first test in the binary) paid that read inside `detect`'s 10 s. Evidence: a passing Delivery takes 0.04 s (baseline lab-gotest at 2be63650: detection normally ends in milliseconds, as the self-signed target fails verification at once); in the failing runs `verifyTarget`, the same handshake with the test's own roots, finished within the 10 ms that Delivery's 10.01 s leaves beside detect's 10 s, so the process wasn't starved; the system-roots read is detection's only work that verifyTarget doesn't do, and the only one that waits on the disk; detection had ended by the next subtest, whose Listen passed; and a targeted re-run (warm page cache, lighter load) passed 3 of 3. Not measured: how long the cold read took in the failing runs (no log of it). The conformance fixture now logs how long the process's first read of the system roots took ("the first read of the system roots took …", in every lab log of the package). **If `didn't complete … in 10s` recurs in Delivery, this cause is ruled out.**

**Forced repro:** `TestListenDoesntChargeTheSystemRootsToTheTarget` (linux) re-runs itself with `SSL_CERT_FILE` a FIFO (and `SSL_CERT_DIR` an empty path; the inherited ones are dropped) that it holds shut for `detectWait`+0.5 s once the child opens it, with the child's `detectWait` at 2 s (now a var for this). The child runs with `-test.timeout=30s` and is killed at 35 s or when the test ends; the parent's waits are bounded by the same 35 s. Before the fix (d8029347) it fails with the lab's message, `didn't complete a TLS handshake for every server name in 2s`; after it, it passes 5 of 5.

**Fix:** Listen reads the system roots (`x509.SystemCertPool()`) before `verifyTarget` and `detect`, so neither 10 s counts a local disk read (`listener.go`, `openListener`, `readSystemRoots`). The read runs on a goroutine of its own, once per process, so a Listen whose context ends during it returns then (`TestListenStopsWhileTheSystemRootsAreRead`, linux, the same FIFO). The bounds stay 10 s; no retries.

**Runs** (all lab-gotest and go test on the remote runner, head named):
- d8029347 (test, no fix): the forced repro fails (above).
- 9a15267a: forced repro 5/5; `make lab-gotest PKG=./internal/dataplane/transport/reality RUN='^TestConformance$' COUNT=20` passed 20/20 in 232 s with other labs running (load average 15, 31 containers); `make lint` and `make test` green. Note: COUNT=20 runs in one process, so the roots are read once per run of the binary; the repro is what proves the cold read is no longer charged.
- dbd581c1 (rewrite merged in): the whole package in a lab node, `make lab-gotest PKG=./internal/dataplane/transport/reality`, passed (55 tests, 1 skip) in 138 s, under similar load.

## Review findings
Four reviewers (one of another model family) agree the fix (the system pool read before both 10 s waits) is correct; the cause is plausible but unmeasured.
- [x] R1.1 (should-fix, proven) RESIDUAL-RISKS.md RR31, doc.go and these Notes get the CCS probing wrong. REALITY's detection runs once per server process per (target, server name, ALPN) (record_detect.go LoadOrStore), again only after a stalled detection is re-run or a restart; handoff workers never probe; not per Listen, not periodic, not triggerable by a prober. A target that refuses (nginx) gets only the burst of 2 extra ChangeCipherSpec records (sendProbePayload stops at the first alert); 15 and 16 reach only targets that tolerate more. nginx's `[crit] … unexpected ccs message` line carries the client IP, which is the server's IP: whoever runs (or can compel) the camouflage site learns the address of every REALITY server using it, timed to restarts (with RR32's shared targets, one site's log is a census); a passive observer of the server's uplink sees the cleartext CCS records and the detection's HelloGolang ClientHellos. Stock REALITY/Xray does the same, so it marks "a REALITY server", not thinkpol. Rewrite RR31, add a new RR row "start-up target detection labels the server's IP to the target's operator" (why accepted: the pinned REALITY has no switch to skip the CCS probe; mitigation tracked in a follow-up ticket). "Not removable without patching REALITY" is open (pre-storing the records from thinkpol's own detection may work), tracked in that ticket. doc.go: "reads them from disk" is Linux/BSD only; the "Before either" sentence goes ahead of the paragraph it refers to.
- [x] R1.2 (should-fix) listener_linux_test.go: the child has no -test.timeout and nothing kills it; the parent's waits are unbounded; an inherited SSL_CERT_FILE wins. exec.CommandContext with a deadline and `-test.timeout`, kill the child in t.Cleanup, bound both waits, clear SSL_CERT_FILE/SSL_CERT_DIR in the child's env except the FIFO; shorten the 3 s hold if it stays meaningful.
- [x] R1.3 (should-fix, falsifiability) The cause is unmeasured: log how long the first SystemCertPool() took, and say in Notes: "if `didn't complete … in 10s` recurs in Delivery, this cause is ruled out".
- [x] R1.4 (nit) listener.go: the pool read ignores ctx, so a stop during a stuck bundle waits out the read; make ctx cancellation still return if it stays simple, else note it.
- [x] R1.5 (ticket) Box "20 runs under load": COUNT=20 runs in one process, so the roots are read once; say the forced repro is the proof and the 20 runs show no other regression.
- [x] R2.1 (nit) RESIDUAL-RISKS.md RR66 and doc.go say "the detection's Go-fingerprinted ClientHellos"; record_detect.go uses HelloChrome_Auto for the h2 case, so of the 6 connections per server name 4 send Go's ClientHello and 2 Chrome's: say exactly that.
- [x] R2.2 (nit) listener_linux_test.go: under extreme load, more than 100 ms between WithTimeout and the read's once.Do makes Listen return before the child opens its CA bundle ("the child never read its CA bundle"). Start the timeout after the read has begun.

## Log
- 2026-11-19 created in backlog (seen in lab runs 2026-11-19)
- 2026-11-19 backlog → in-progress, owner: agent-tp-253
- 2026-11-19 cause: REALITY's detection read the system roots from disk inside Listen's 10 s detect wait; nginx's ccs lines are REALITY's own CCS-tolerance probe (documented, RR31). Fix: Listen reads the roots first. Forced repro TestListenDoesntChargeTheSystemRootsToTheTarget fails at d8029347, passes at 9a15267a
- 2026-11-19 mutation: the fix removed (d8029347, the test alone) fails the forced repro with the lab's message; restored at 9a15267a, 5/5 pass
- 2026-11-19 runs: TestConformance COUNT=20 lab-gotest under load 20/20 (9a15267a, 232 s); make lint, make test green (9a15267a); reality package lab-gotest passed (dbd581c1, 138 s)
- 2026-11-19 full make lab-test at 45f7f9e4: every test passed, transport/reality's node phase included; exit 3, OVER BUDGET (default stream 41m23s > 15m0s, with other branches' labs running at once; slowest TestRealityStockXray 15m25s, not this ticket's); wall time 2485 s
- 2026-11-19 not verified: how long the cold read of the system roots took in the failing runs (they logged nothing of it); the cause rests on the forced repro and the failing runs' timings (Notes)
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: fix R1.1–R1.5
- 2026-11-19 R1.1–R1.5 fixed (c542fd17): RR31 points to a new RR66 (start-up target detection labels the server's IP to the target's operator, ticket TP-256), doc.go (roots paragraph moved ahead, Linux/BSD only; detection once per process, not per Listen) and transports.md; readSystemRoots reads the roots once per process on a goroutine and returns when ctx ends; the conformance fixture logs the first read's time; the forced repro's child gets -test.timeout=30s, is killed at 35 s or the test's end, the parent's waits are bounded, its CA env is its own, the hold is 2.5 s; new TestListenStopsWhileTheSystemRootsAreRead; Notes and the 20-runs box corrected
- 2026-11-19 mutations, each caught (in a local copy, not pushed): the pre-read removed (old order) fails the forced repro with "didn't complete a TLS handshake for every server name in 2s"; the read made synchronous fails TestListenStopsWhileTheSystemRootsAreRead ("Listen returned 2.5s after its context ended at 100ms: it waited for the system roots"); both tests pass 5/5 on c542fd17
- 2026-11-19 runs on c542fd17: make lint, make test green; GOOS=darwin go build and go vet of the package; make lab-gotest PKG=./internal/dataplane/transport/reality RUN='^TestConformance$$' passed (Delivery 0.06 s; "the first read of the system roots took 38.033678ms")
- 2026-11-19 not verified: the forced repro's own timeout paths (no run hung the child); no full make lab-test (brief: targeted runs only)
- 2026-11-19 filed TP-256 (start-up detection without the CCS probe) and TP-257 (handoff workers' ChangeCipherSpec tolerance) on rewrite; TP-256's refs gain RR66 in this branch, where RR66 lands
- 2026-11-19 has-errors → review
- 2026-11-19 review round 2: nits R2.1–R2.2, merge
- 2026-11-19 runs on 3b2ef906: go test ./internal/dataplane/transport/reality/... -count=3 and the two SystemRoots tests -count=10 pass; make lint, make test green. R2.2 not mutation-checked: the failure needs a load-timed gap, which no mutation reproduces deterministically
