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
- [ ] A test that the re-check times of a target whose check keeps failing are not on a fixed grid (not all multiples of one period).
- [ ] RESIDUAL-RISKS.md RR66, reality's doc.go and docs/design/transports.md describe the new spacing.

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
