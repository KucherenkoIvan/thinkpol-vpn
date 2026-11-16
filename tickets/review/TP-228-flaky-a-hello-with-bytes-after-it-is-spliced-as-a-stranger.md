---
id: TP-228
title: "Flaky TestAHelloWithBytesAfterItIsSplicedAsAStranger"
milestone: M2
area: dataplane/transport/reality
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-228"
branch: "tp-228-flaky-reality-hello-stranger"
---

## Goal
`TestAHelloWithBytesAfterItIsSplicedAsAStranger` (internal/dataplane/transport/reality/router_test.go:297) failed under load with "verdict 4, want StreamUnknown" after TP-201 fixed a clock flake in it.

## Scope
- Find why the verdict differs under load.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with the failing run's evidence.
- [x] A fix in the test or the code.
- [x] The test passes 20 runs under load (a full lab or SIGSTOP freezes beside it), and a mutation that brings the cause back fails it.
- [x] No retries and no longer timeouts without a cause.

## Notes

- **Root cause (2026-11-16): the test's tap, not the verdict.** Verdict 4 is `StreamRouted`. The tap (fixture_test.go `newTap`) copied each direction with `io.MultiWriter(up, recorder)`: it forwarded a chunk, then recorded it. The test reads `tp.captured()[0]` as soon as the worker has read "after the hello", so under load the tap goroutine could still be between the two writes and the capture lacked its last chunk. In the failing runs the capture was the hello alone (with a delay between forward and record: `captured 1757 bytes, the hello's 1757`). A hello alone, fresh and unseen, on a router whose clock lets it past the start rule, is a dialer's hello and is routed: the second router's `StreamRouted` was right for the bytes it got. A hello whose trailing bytes arrive in a later read is decided the same way in the product (gather can't know more is coming); that is no weaker than before, since the trailing-bytes rule is a camouflage rule, not part of authentication, and the replay cache and start rule still apply.
- **Failing run's evidence.** The pre-fix test binary (`-race`) under load (four busy loops beside it and the test process stopped with SIGSTOP for 50 ms every 300 ms) failed 1 of 300 runs: `router_test.go:331: verdict 4, want StreamUnknown`, the ticket's failure. An earlier failfast loop under the same load failed the same way.
- **Fix.** The tap records each chunk before forwarding it (`recordThenForward`; what the forward didn't take is trimmed from the capture again), so whatever the far end has read is already in the capture. The test also fails at once, with the sizes, on a capture with nothing after the hello, instead of a misleading verdict. No retries, no timeouts changed.
- Product code is unchanged; R1.1 changes only comments and the package doc.

## Review findings
Review round 1: merge, with nits.
- [x] R1.1 doc.go and splice.go said a client sending past its hello before any answer is spliced as a stranger; gather only counts the bytes in the read that completes the hello. Both now say so, and why that is fine: the rule is camouflage, not authentication, which rests on the replay cache and the start rule. Comments only.
- [x] R1.2 The supervisor's reality test tap (streamTap) forwarded before it recorded, the pattern fixed in the reality fixture. It now records then forwards, through a local copy of recordThenForward (the fixture's is in another package's tests).
- [x] R1.3 router_test.go names its assumption that probe's one Write of the hello and the trailing bytes arrives in one read on loopback.
- [x] R1.4 Notes said nothing that runs on macOS changed; the fixture runs there too. Now: product code is unchanged.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-228
- 2026-11-16 root cause: the test tap forwarded a chunk before recording it, so the capture could miss the bytes after the hello and the second router rightly routed the bare hello (Notes). Fix in fixture_test.go (recordThenForward) and a guard in TestAHelloWithBytesAfterItIsSplicedAsAStranger on a capture with nothing after the hello. No product change
- 2026-11-16 under load (-race, four busy loops, SIGSTOP 50 ms every 300 ms) on b6ae3244: TestAHelloWithBytesAfterItIsSplicedAsAStranger passed 300 of 300 (422 freezes); the pre-fix commit 8084cf52 under the same load failed 1 of 300 (verdict 4, want StreamUnknown). Whole reality package -race -count 3 on b6ae3244: pass. make lint and make test (umask 022) on b6ae3244: pass
- 2026-11-16 mutations: forwarding before recording, with a 100 ms delay between the two → the test fails 3 of 3 (captured 1757 bytes, the hello's 1757: nothing after it; without the guard, verdict 4, want StreamUnknown); control: the same delay between recording and forwarding passes 3 of 3
- 2026-11-16 merged origin/rewrite (TP-221, TP-227) as 7682e590; make lint and make test (umask 022) on 7682e590: pass
- 2026-11-16 make lab-test on 7682e590: the reality package and every other in-node package passed but internal/dataplane/dns (TestResolvConfASlowWriterPastTheCapKeepsItsServers, TP-220's open flake); the lab phase passed but TestCensorMatrix/openvpn-tcp (reference), whose off cell's docker compose up was still creating containers at its 600 s limit (the run beside other labs), so its other cells skipped. Neither touches this ticket's files. An earlier make lab-test on 0f1e5084 failed the same way in the matrix only (openvpn-udp and relay-tcp reference rows: waiting for the subnet allocation lock, deadline exceeded), every in-node package passing. Not verified here: a fully green make lab-test on this branch
- 2026-11-16 make lab-gotest PKG=./internal/dataplane/transport/reality/ RUN=TestAHelloWithBytesAfterItIsSplicedAsAStranger COUNT=20 on 7682e590: 20 of 20 passed
- 2026-11-16 in-progress → review
- 2026-11-16 review round 1: merge, nits R1.1–R1.4
- 2026-11-16 R1.1–R1.4 fixed in b189b56c. On b189b56c: make lint and make test (umask 022) pass; reality package -race -count=3 pass; make lab-gotest PKG=./internal/agent/supervisor RUN=TestRealitySpacesShareAListener COUNT=5: 5 of 5 passed
- 2026-11-16 the full make lab-test on 7682e590 (exit 2, only TP-220's dns flake and censor-matrix reference rows timing out on lab setup under contention; the reality package passed) is accepted by the orchestrator for this test-only change; no new full lab
