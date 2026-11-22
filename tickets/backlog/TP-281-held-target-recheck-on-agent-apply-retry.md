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
owner: ""
branch: ""
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

## Log
- 2026-11-22 created in backlog (from TP-230's review)
