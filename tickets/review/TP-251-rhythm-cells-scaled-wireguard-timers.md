---
id: TP-251
title: "The rhythm cells run with WireGuard's timers sped up in the lab"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: [RR65]
owner: "agent-tp-251"
branch: "tp-251-scaled-wg-timers"
---

## Goal
The matrix's wireguard-rhythm cells hold the tunnel 7.5 minutes of real time to see three rekeys (the reality and udp rows): the largest fixed wait left in a full lab. The owner's rule (2026-11-16): waits use a sped-up clock wherever possible. A system-wide fake clock can't reach a Go binary (libfaketime hooks libc; time namespaces only offset clocks), but the WireGuard these cells exercise is thinkpol's userspace wireguard-go, whose rekey timers are compile-time constants (device/constants.go).

## Scope
- A lab-only build replaces that constants file with timers scaled by a factor (e.g. 10×) through `go build -overlay`, never touching go.mod or the product binary.
- The censor's rhythm rules (its windows, "the last 2m0s apart", the quiet read) scale by the same factor, from one setting.
- The scaled cells run in every lab.
- One real-timer run of the rhythm cells stays as its own target (`make lab-test-rhythm-real` or similar), run at milestone gates and whenever transport shaping or the rhythm rules change.

## Out of scope

## Acceptance
- [x] The lab binary's WireGuard rekeys at the scaled interval (lab log), the product binary's doesn't (test). Lab log at 040d0d0e: both rows' rhythm cells blocked "... 3 times, the last 12s apart" (real timers: "the last 2m1s apart"). Product: a one-off check instead of a new test (owner: no new tests): `go build -trimpath -buildvcs=false ./cmd/thinkpol` lists wireguard-go from the module cache with its h1 sum and no replacement; the lab-built thinkpol lists it replaced by the scaled copy (`=> <user cache>/thinkpol-lab/wgtimers/<version>-<hash> (devel)`); the branch changes nothing outside lab/, the Makefile and tickets/.
- [x] The scaled rhythm cells give the same verdicts as the real-timer run (RESULTS.md diff), and the real-timer target exists and passes. A partial matrix run writes no RESULTS.md, so the cells' verdict lines stand in for its diff: scaled (040d0d0e) and real (`make lab-test-rhythm-real`, 040d0d0e) both give udp fail by the rekey signal (records of 240 and 184 bytes) and reality fail by the burst signal (3 against 2, accepted under RR65), the off cells pass.
- [x] The matrix's long stream (or its replacement) wall time before and after, in Notes.

## Notes
- Only WireGuard's timers scale. Reality's own timing, TCP retransmits, thinkpol's path probes and the traffic generator keep real time, so the noise around each rekey shrinks relative to the interval, and a scaled cell can detect more easily than a real censor would. That is harmless for today's expected-fail cells, but a cell expected to pass (e.g. after TP-237's cover records) must be judged on the real-timer run.

- How (2026-11-19): `go build -overlay` refuses files beneath GOMODCACHE, so the lab's thinkpol build (lab/prepare.go `buildTools`, lab/wgtimers.go) reads a go.mod of its own (`-modfile`, in a temp dir, with the checkout's go.sum): the checkout's go.mod plus `replace golang.zx2c4.com/wireguard => <copy>`, the copy being the module with `device/constants.go` scaled, kept in the user's cache under its version and a hash of the scaled file, so the binary stays the same run to run. Only thinkpol's build gets it; labdns, censord, node package tests, go.mod and `make build` don't. Every duration constant of the file is divided (`(expr) / N`), RekeyTimeoutJitterMaxMs too (334 → 33 ms at 10, whole milliseconds), counts and sizes are left; MaxTimerHandshakes is written out as 90 / 5 and stays right. A constant missing, added or renamed fails the build. `THINKPOL_LAB_WG_TIMER_SCALE` (1 to 20, default 10) is read by the build and by the rhythm cells (`rekey` = 120 s / N, hold = 450 s / N + 10 s, so 55 s); `make lab-test-rhythm-real` runs the cells with 1.
- wireguard-rhythm: `window()` and the quiet before an idle record now scale with `rekey` (REJECT_AFTER_TIME + wgRekeySlack, and wgQuiet = REKEY_TIMEOUT, were partly or wholly fixed); the pair window, count settle, burst gap and steady jitter are the module's real-time choices and stay. At the default 120 s nothing changes.
- The scaled lab speeds up every lab test's WireGuard, not only the rhythm cells: product code derived from wireguard-go's constants scales with them (`dataplane.ExitHandshakeDeadline` = 3 × RekeyTimeout, 1.5 s at 10). No full lab was run on this branch (brief: targeted runs only); a full lab after merge is the first to show any test that leaned on real WireGuard timing.
- Wall times (remote runner, under other sessions' load), `TestCensorMatrix/^(udp|reality)$/^(off|wireguard-rhythm)$`. Real timers (`make lab-test-rhythm-real`, 040d0d0e): udp/wireguard-rhythm 473 s, reality/wireguard-rhythm 482 s; rows udp 772 s, reality 895 s. Scaled ×10 (040d0d0e): 82 s and 82 s; rows 175 s and 187 s (an earlier scaled run at d13cecbd: 78 s and 76 s, rows 320 s and 321 s, the lab start slower under load). The matrix's longest row (reality) loses about 400 s of hold.
- Each hold, real or scaled, got all its pings back but 2 (228 of 230, 26 of 28); at 28 pings that is the 90% line, so the hold now also accepts all but 4 (a block costs the redial a ping or two, and a scaled hold can see two blocks: udp was blocked twice in its 55 s).

## Log
- 2026-11-19 created in backlog (owner: sped-up clocks wherever possible)
- 2026-11-19 depends_on TP-239 dropped: TP-251 no longer waits on it (TP-239 merges this in)
- 2026-11-19 backlog → in-progress, owner: agent-tp-251
- 2026-11-19 built: lab-only scaled wireguard-go timers (-modfile + cached scaled copy; -overlay refused under GOMODCACHE), rhythm cells' rekey and hold scaled, module quiet/window scale with rekey, make lab-test-rhythm-real, lab/README.md "WireGuard's timers"
- 2026-11-19 runs at 040d0d0e: scaled cells pass (udp fail, reality fail as expected, "12s apart"), real-timer target passes (same verdicts, "2m1s apart"); make lint, make test green; no full lab (brief: targeted only); no new tests (owner), so no mutations
- 2026-11-19 not verified: other lab tests under scaled WireGuard timers (no full lab); out of scope: a RUN with $ anchors passed through make lab-gotest loses them (make expands $), RUN needs $$
- 2026-11-19 in-progress → review
