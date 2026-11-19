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
- [x] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
**The failure wasn't the ChangeCipherSpec.** Both lab failures (TP-239's runs at 9632e30b and one before it) say the same thing: `TestConformance/Delivery (10.01s)` failed at `reality: target 127.0.0.1:… didn't complete a TLS handshake for every server name in 10s`. That is `detect` in Listen: REALITY's detection of the shared Go target's records didn't end within `detectWait`. nginx's three `unexpected ccs message` lines come from another test of the package (`TestAfterTheLabSitesFINTheSameWriteFails`, the only one that starts nginx) and appear in passing runs too: the full-lab logs of three other branches have the same three lines, and so does this branch's passing lab-gotest of the package.

**What sends the CCS nginx doesn't expect:** REALITY itself. At each detection (`DetectPostHandshakeRecordsLens`, xtls/reality `record_detect.go`) it opens, per server name and ALPN, a second connection (`CCSDetectConn`) that sends the target 2, then 15, then 16 extra ChangeCipherSpec records, a second apart, to learn how many the site tolerates (REALITY's server then tolerates as many, `GlobalMaxCSSMsgCount`). OpenSSL refuses the first burst, hence one `[crit] … unexpected ccs message` per ALPN, three per Listen. **A censor can see this**, but not through a probe: it happens once per listener opened, on the server-to-target leg, so the site's operator (in its error log) and whoever watches that leg see a REALITY listener open. A probe or client can't make the server forward a half-done handshake this way. Upstream behaviour, not removable without patching REALITY: documented in the package doc and in RR31; whether it deserves its own residual or ticket is the owner's call.

**Root cause of the flake.** REALITY's detection verifies the target with utls against the system roots (its Config has no RootCAs). crypto/x509 reads the system roots from disk once per process, on first use: on the lab image (Debian, ca-certificates) that is the bundle plus each certificate file in `/etc/ssl/certs`, on the overlay of a node whose Docker storage is on a loaded spinning disk, with no bound. With `TrustTargetRoots` (every test and the lab), `verifyTarget` doesn't touch the system roots, so the package's first Listen (TestConformance/Delivery, the first test in the binary) paid that read inside `detect`'s 10 s. Evidence: a passing Delivery takes 0.04 s (baseline lab-gotest at 2be63650: detection normally ends in milliseconds, as the self-signed target fails verification at once); in the failing runs `verifyTarget`, the same handshake with the test's own roots, finished within the 10 ms that Delivery's 10.01 s leaves beside detect's 10 s, so the process wasn't starved; the system-roots read is detection's only work that verifyTarget doesn't do, and the only one that waits on the disk; detection had ended by the next subtest, whose Listen passed; and a targeted re-run (warm page cache, lighter load) passed 3 of 3. Not measured: how long the cold read took in the failing runs (no log of it).

**Forced repro:** `TestListenDoesntChargeTheSystemRootsToTheTarget` (linux) re-runs itself with `SSL_CERT_FILE` a FIFO that it holds shut for `detectWait`+1 s once the child opens it, with the child's `detectWait` at 2 s (now a var for this). Before the fix (d8029347) it fails with the lab's message, `didn't complete a TLS handshake for every server name in 2s`; after it, it passes 5 of 5.

**Fix:** Listen reads the system roots (`x509.SystemCertPool()`) before `verifyTarget` and `detect`, so neither 10 s counts a local disk read (`listener.go`, `openListener`). The bounds stay 10 s; no retries.

**Runs** (all lab-gotest and go test on the remote runner, head named):
- d8029347 (test, no fix): the forced repro fails (above).
- 9a15267a: forced repro 5/5; `make lab-gotest PKG=./internal/dataplane/transport/reality RUN='^TestConformance$' COUNT=20` passed 20/20 in 232 s with other labs running (load 15.3 on 6 cores, 31 containers); `make lint` and `make test` green. Note: COUNT=20 runs in one process, so the roots are read once per run of the binary; the repro is what proves the cold read is no longer charged.
- dbd581c1 (rewrite merged in): the whole package in a lab node, `make lab-gotest PKG=./internal/dataplane/transport/reality`, passed (55 tests, 1 skip) in 138 s, load 18.2.

## Log
- 2026-11-19 created in backlog (seen in lab runs 2026-11-19)
- 2026-11-19 backlog → in-progress, owner: agent-tp-253
- 2026-11-19 cause: REALITY's detection read the system roots from disk inside Listen's 10 s detect wait; nginx's ccs lines are REALITY's own CCS-tolerance probe (documented, RR31). Fix: Listen reads the roots first. Forced repro TestListenDoesntChargeTheSystemRootsToTheTarget fails at d8029347, passes at 9a15267a
- 2026-11-19 mutation: the fix removed (d8029347, the test alone) fails the forced repro with the lab's message; restored at 9a15267a, 5/5 pass
- 2026-11-19 runs: TestConformance COUNT=20 lab-gotest under load 20/20 (9a15267a, 232 s); make lint, make test green (9a15267a); reality package lab-gotest passed (dbd581c1, 138 s)
