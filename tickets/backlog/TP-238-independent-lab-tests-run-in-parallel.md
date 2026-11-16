---
id: TP-238
title: "Independent lab tests run in parallel; tests that must run alone get their own stream"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-200]
refs: []
owner: ""
branch: ""
---

## Goal
The `lab/` package runs its tests one after another, and the teardown tests that can't share the host run first, adding ~14.5 min before anything parallel.

The owner (2026-11-16): a full lab must take at most ~15 minutes on the remote runner; waits only where no watcher can tell, otherwise a sped-up clock; long-wait tests in a separate stream that never blocks others; everything that can run in parallel must. Measured on the remote runner (2026-11-16): the `lab/` package alone took ~46 min; the host-wide subnet allocation lock is held for each lab's whole `docker compose up --wait` (10–45 s per lab), so lab starts are serialized across every run (~92% busy); non-parallel teardown tests add a ~14.5-minute serial prefix before parallel tests resume.

## Scope

## Out of scope

## Acceptance
- [ ] Every `lab/` test that doesn't need the host to itself runs in parallel with the others (list in Notes which can't, and why).
- [ ] Tests that truly must run alone run in their own stream, alongside the parallel tests instead of in front of them.
- [ ] No new flakes: the changed tests pass 3 full labs in a row on the remote runner.
- [ ] The `lab/` package's wall time before and after, in Notes.

## Notes
Depends on TP-200 (it changes how lab tests start nodes, in many of the same files): build on it.

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority)
