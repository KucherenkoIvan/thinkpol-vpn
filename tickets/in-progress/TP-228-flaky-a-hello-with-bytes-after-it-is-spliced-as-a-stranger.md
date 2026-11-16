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
- Product code is unchanged; nothing that runs on macOS changed.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-228
- 2026-11-16 root cause: the test tap forwarded a chunk before recording it, so the capture could miss the bytes after the hello and the second router rightly routed the bare hello (Notes). Fix in fixture_test.go (recordThenForward) and a guard in TestAHelloWithBytesAfterItIsSplicedAsAStranger on a capture with nothing after the hello. No product change
- 2026-11-16 under load (-race, four busy loops, SIGSTOP 50 ms every 300 ms) on b6ae3244: TestAHelloWithBytesAfterItIsSplicedAsAStranger passed 300 of 300 (422 freezes); the pre-fix commit 8084cf52 under the same load failed 1 of 300 (verdict 4, want StreamUnknown). Whole reality package -race -count 3 on b6ae3244: pass. make lint and make test (umask 022) on b6ae3244: pass
- 2026-11-16 mutations: forwarding before recording, with a 100 ms delay between the two → the test fails 3 of 3 (captured 1757 bytes, the hello's 1757: nothing after it; without the guard, verdict 4, want StreamUnknown); control: the same delay between recording and forwarding passes 3 of 3
