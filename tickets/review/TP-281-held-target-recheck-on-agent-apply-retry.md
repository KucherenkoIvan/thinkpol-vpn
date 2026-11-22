---
id: TP-281
title: "A held target re-check lands on the agent's 5 s apply retry"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: [RR66]
owner: "agent-tp-281"
branch: "tp-281-recheck-off-the-retry-grid"
---

## Goal
While a reality target's check keeps failing, the server's re-checks of it are not spaced on a fixed grid, so a censor on the server's uplink can't tell them by their period while the target stays down.

## Scope
- Today a held check runs again only when the agent's apply retry calls Listen (`serverSpaces.run`, `internal/agent/node.go`, every `RetryAfter`, 5 s, after the last apply). reality's backoff (`internal/dataplane/transport/reality/targetcheck.go`) draws each wait at random, but the re-check is made at the first retry after the wait ends, so re-checks are whole multiples of 5 s apart (plus the applies' own time), which folding the times by 5 s shows.
- Ideas: jitter the apply retry (e.g. 3–7 s at random), or schedule a retry at the held check's own deadline (Listen's error could carry it).

## Out of scope
- reality's own backoff bounds (TP-230 set them).

## Acceptance
- [x] A test that the re-check times of a target whose check keeps failing are not on a fixed grid (not all multiples of one period). `TestAHeldTargetIsCheckedAgainOffTheRetryGrid` (internal/agent/heldtarget_test.go:36): the real reality transport on a fake clock (also driving the server's retry timer), a local target that fails every check, 25 checks; for no period P from 100 ms to 10 s in 10 ms steps are all 24 gaps within 10 ms of a multiple of P; each gap is within [least wait, wait's top + 7 s] for its failure count; every Listen call after the first follows a retry timer of the test's (both call sites of retryIn); the retry waits lie in 3–7 s, span below 3.5 s and above 6.5 s, and average 5 s ± 5σ. Mutations in the Log.
- [x] RESIDUAL-RISKS.md RR66, reality's doc.go and docs/design/transports.md describe the new spacing. RESIDUAL-RISKS.md:69 (RR66's scope column), reality doc.go:156-181, docs/design/transports.md:19; each gives the 3–7 s retry, the re-check gaps (wait + 0–7 s: 5–17, 10–27, 20–47, 40–87, then 60–127 s, plus the check's own time, up to 10 s, 20 s if detection stalls) and what a censor still sees (the series of hellos to one target every 1–2 min while it stays down). Also targetcheck.go's comment, agent.RetryAfter's doc and lab idleHold's comment.

## Notes
- Found in TP-230's final check (2026-11-22).
- **Choice: (a), jitter the server's apply retry** (`serverSpaces.retryIn`, internal/agent/node.go). It is a few lines in one place, needs nothing carried across the supervisor (Listen's error passes through `Supervisor.SetListeners`' `errors.Join` and `errListeners`), and keeps every other failure's retry as it was on average. (b), retrying at the held check's own deadline, would need a typed error from reality through the supervisor, a min over every failed listener and the 5 s for other failures, and a clamp for deadlines in the past; it would not by itself take re-checks off the grid when another listener or SetSpaces also fails, since the retry would then be the 5 s one again.
- **The wait:** uniform over 60%–140% of `retryAfter` (3–7 s for `RetryAfter`), mean 5 s, so no slower on average for other apply failures; bounded both ways (never under 3 s, so no tight loop). Drawn from math/rand/v2's top-level generator, as reality's `checkBackoff` is: it is ChaCha8 seeded from the OS per process, so the draws can't be predicted from outside, and the jitter is no secret that would need crypto/rand. Listen while held still fails at once without dialling (unchanged, targetcheck.go).
- **Clock:** reality's `targetChecks` now reads `Options.Now` (nil: time.Now) instead of always the real clock, so a test can run the real held check on a fake clock. Production passes no `Now`.
- **What stays visible** (RR66, doc.go, transports.md): re-checks come 0–7 s after their wait ends (5–17 s, 10–27 s, 20–47 s, 40–87 s, then 60–127 s apart), on no one period; a censor still sees the series of short hellos to one target, gaps growing to 1–2 min and staying there while it stays down.
- Device-mode data planes (`listenerSet`, internal/agent/dataplane.go) still retry listeners every `RetryAfter`, but a device has no listeners (netmap section.go: "a device has no listeners") and a server's worker opens none itself (its listeners are the supervisor's, SharedInbound), so no reality check runs on that grid; left as is.

## Log
- 2026-11-22 created in backlog (from TP-230's review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-281
- 2026-11-22 implemented (d04a54a0): idea (a), the server's apply retry waits a uniform 3–7 s (`serverSpaces.retryIn`, internal/agent/node.go:1115, used at :1059 and :1101); reality's target-check backoff reads Options.Now (transport.go:53); docs RR66, reality doc.go, transports.md. Why (a) over (b): Notes.
- 2026-11-22 test TestAHeldTargetIsCheckedAgainOffTheRetryGrid passes, 200/200 with -count=200. Mutations (run locally, not pushed): retry back to a fixed `retryAfter` → fails ("every gap is within 50ms of a multiple of 1s", gaps 10s 15s 35s 1m5s …); retry 5–9 s (slower) → fails ("a retry after 7.84s, want 3 to 7 s"). reality package unit tests pass with the clock change.
- 2026-11-22 make lint exit 0 (466 s), make test exit 0 (300 s), both at d04a54a0; lab run `make lab-gotest PKG=./internal/dataplane/transport/reality/...` at d04a54a0: exit 0, 94 s. No full lab run (the brief asks for none; the orchestrator runs full labs on rewrite). The reality matrix's setup was not re-run: only a comment changed there (idleHold). Merged origin/rewrite (3b28a2fd, a board-only change).
- 2026-11-22 in-progress → review
- 2026-11-22 review fixes: RR66 (RESIDUAL-RISKS.md:69), reality doc.go:156-181 and transports.md:19 add the check's own time to the gaps (the wait starts once the check ended: up to 10 s, 20 s if detection stalls), say a constant check time brings no period back and that a target that silently drops packets sees only SYNs; transports.md "at every retry" for "every 5 s"; doc.go paragraph reflowed. targetcheck_test.go: stale TP-281 remark dropped. node.go retryIn comment: "averaging retryAfter".
- 2026-11-22 review fixes, test (heldtarget_test.go): period scan from 100 ms (was 1 s) with a 10 ms tolerance (was 50 ms); `least` renamed `top`; `sigma` named; every Listen call after the first must follow a retry timer of the test's, which covers the first call site (node.go:1059). Mutations (local, not pushed): retry `3s + rand.N(9)*500ms` → fails ("every gap is within 10ms of a multiple of 100ms", gaps 7s 14s 22s 1m21.5s …; passed with the old 1 s scan); first call site back to `time.After(s.retryAfter)` → fails ("Listen call 2 came after 0 retry timers"; the old test passed, only 5 s slower).
