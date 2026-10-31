---
id: TP-165
title: "udp start rule: pin the clock handling"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: S
depends_on: [TP-069]
refs: [RR34]
owner: ""
branch: ""
---

## Goal
The start rule's clock handling (TP-069) is pinned by tests or stated where a reader of the code would look, so a later change can't quietly undo it.

## Scope
Files: internal/dataplane/transport/udp/admit.go, internal/dataplane/transport/udp/transport.go.
- (a) The default `Transport.elapsed` (transport.go:52, `now.Sub(start)`) relies on both readings carrying time.Now's monotonic clock, so a wall-clock step doesn't count. No test catches its loss: a `now.Round(0).Sub(start)` mutation passes every test. Pin it with a test that does fail on that mutation, or, if no test can tell without a real clock step, with a comment at transport.go:52 saying why it must stay as it is.
- (b) `startRule.refuses` (admit.go:43-49) refuses nothing when `elapsed` is nil, which is also the zero startRule's "no start rule" (the dialer's, a Listener behind a Router). A `Transport` built without `New`, or a future `startedAt` (admit.go:32-34) with a nil `elapsed`, silently turns the rule off. Make `startedAt` fail loudly on a nil `elapsed`, or give the rule an explicit "on" flag apart from `elapsed`.
- (c) `Options.Now`'s doc (transport.go:29-31) should say that a clock with no monotonic reading (a custom `Now`) undoes the step handling: wall-clock steps then count as elapsed time.
- (d) Start-rule drops count as `StaleTimestamp` (`dropStaleTimestamp`, admit.go:82-84; counters at transport.go:170). Consider a separate counter, so a peer still sending from before a restart can be told apart from a stale capture. If added, it goes through the counters wherever `StaleTimestamp` is reported.
- (e) No test pins RR34's "sender clock ahead" residual: a capture from a sender whose clock ran ahead of the node's by more than the time from the capture to the restart is let in. Add one.

## Out of scope
- Changing what the start rule accepts or RR34's decision (TP-069, decided).
- A real NTP step or a real supervisor process restart in the lab.

## Acceptance
- [ ] (a) the monotonic-clock reliance is pinned: a test that fails on `now.Round(0).Sub(start)`, or a comment at the default `elapsed` saying why no test can
- [ ] (b) a start rule with a nil `elapsed` can no longer be built by mistake, or no longer means "off"; a test shows it
- [ ] (c) `Options.Now`'s doc says what a clock without a monotonic reading does
- [ ] (d) a separate counter for start-rule drops, with a test, or a Notes line saying why not
- [ ] (e) a test of the sender-clock-ahead residual: such a capture is let in, as RR34 says
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-069's final check and fix round (tickets/done/TP-069-replays-after-supervisor-restart.md, last Log line): nits for a follow-up, (a) to (c) from the final check, (d) and (e) from the fix round.

## Log
- 2026-10-31 created in backlog (TP-069 final check and fix round)
