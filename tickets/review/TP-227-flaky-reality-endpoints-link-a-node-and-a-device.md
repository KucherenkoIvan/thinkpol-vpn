---
id: TP-227
title: "Flaky TestRealityEndpointsLinkANodeAndADevice"
milestone: M2
area: devmap
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-227"
branch: "tp-227-flaky-devmap-reality-endpoints"
---

## Goal
`TestRealityEndpointsLinkANodeAndADevice` (internal/devmap/plan_reality_test.go:79, from TP-201) failed under load with "t.Error after the test returned" (a goroutine reporting after the test ended).

## Scope
- Find the goroutine, make the test wait for it, or fix the code if it outlives its owner.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with the failing run's evidence.
- [x] A fix in the test or the code.
- [x] The test passes 20 runs under load (a full lab or SIGSTOP freezes beside it), and a mutation that brings the cause back fails it.
- [x] No retries and no longer timeouts without a cause.

## Notes
- **Root cause (2026-11-16).** A race in the test, not in the code. The test dialled in a goroutine and returned as soon as the listener's Accept gave it the link; its deferred `cancel()` then ended the dial's context. The listener admits a link once its server handshake has read the client's Finished, and the client writes that Finished before its `HandshakeContext` returns. crypto/tls and utls (v1.8.2, `handshakeContext`) watch the context in a second goroutine: on the way out the handshake closes `done` and takes that goroutine's verdict, which is the context's error when the cancel lands first (or when both are ready and `select` picks it). So a dial whose handshake had finished on the wire returned `reality: TLS handshake: context canceled`, and the goroutine called `t.Error` after the test had returned. Load widens the window between the client's last write and its return, but on Linux it needs none: a plain `go test -race -count 200` failed by the third run. On macOS neither the unfixed test nor the mutation below failed in 200 runs (plain, `-cpu 1,4`, or under freezes).
- **Evidence.** On Linux, `go test -race -run TestRealityEndpointsLinkANodeAndADevice -count 200` of rewrite's test (0bd9315) panicked at the third run:
  ```
  panic: Log in goroutine after TestRealityEndpointsLinkANodeAndADevice has completed: reality: TLS handshake: context canceled
  ...
  github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap.TestRealityEndpointsLinkANodeAndADevice.func2()
  	internal/devmap/plan_reality_test.go:122 +0x213
  ```
  Under SIGSTOP/SIGCONT freezes (gaps 0 to 300 ms, stops 50 to 700 ms) beside two busy loops, it panicked the same way at the second run; the race detector's report beside it is the testing package's own state, written when the test ended and read by that `t.Error`.
- **The fix (test only).** The dial's goroutine sends its link and error on a buffered channel; after Accept the test waits for that result before it returns (and so before the cancel), and asserts the dial's error itself. The goroutine no longer touches `t`. The 10 s timeout is unchanged.
- **The code is right.** A dial cancelled before it returns fails and closes its connection, as crypto/tls's own dial does; the server then holds a link whose far end has gone, which it drops on the read error like any other. No product code changed, so the lab doesn't cover the change and wasn't run.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-227
- 2026-11-16 reproduced on Linux: rewrite's test (0bd9315) under `go test -race -count 200` panicked at the third run, "Log in goroutine after TestRealityEndpointsLinkANodeAndADevice has completed: reality: TLS handshake: context canceled"; under SIGSTOP freezes beside two busy loops at the second; on macOS it passed 200 of 200; diagnosis in Notes
- 2026-11-16 fix (4ef6611, test only): the dial's goroutine sends its link and error on a channel and the test waits for them after Accept, before its deferred cancel; no retries, the 10 s timeout unchanged
- 2026-11-16 on 4ef6611, Linux: `go test -race -count 200` passed 200 of 200, twice; under SIGSTOP/SIGCONT freezes (gaps 0 to 300 ms, stops 50 to 700 ms, 273 freezes) beside two busy loops, `-race`, passed 100 of 100
- 2026-11-16 mutation M1, `cancel()` before the test waits for the dial (the cause back): failed 27 of 200 under `go test -race -count 200` on Linux, each "dial: reality: TLS handshake: context canceled"; on macOS it passed 200 runs plain, with `-cpu 1,4` and under freezes, so it ran on Linux from a patch applied to a local checkout, never pushed, then restored
- 2026-11-16 `make lint` and `make test` green on 4ef6611 (umask 022); no product code changed, so no lab run
- 2026-11-16 out of scope: none found; reality's Dial failing when its context is cancelled after the handshake's last write is crypto/tls's behaviour, and correct for a dial abandoned before it returns
- 2026-11-16 in-progress → review
