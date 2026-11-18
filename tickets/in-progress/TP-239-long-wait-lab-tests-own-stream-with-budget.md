---
id: TP-239
title: "Long-wait lab tests run in their own stream, with a time budget"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-238, TP-223]
refs: []
owner: "agent-tp-239"
branch: "tp-239-long-wait-stream"
---

## Goal
The censor matrix's rhythm holds (7.5 min each) and the 450 s long probe make every full lab wait on them.

The owner (2026-11-16): a full lab must take at most ~15 minutes on the remote runner; waits only where no watcher can tell, otherwise a sped-up clock; long-wait tests in a separate stream that never blocks others; everything that can run in parallel must. Measured on the remote runner (2026-11-16): the `lab/` package alone took ~46 min; the host-wide subnet allocation lock is held for each lab's whole `docker compose up --wait` (10–45 s per lab), so lab starts are serialized across every run (~92% busy); non-parallel teardown tests add a ~14.5-minute serial prefix before parallel tests resume.

## Scope

## Out of scope

## Acceptance
- [ ] The long-wait tests (the rhythm holds, the long probe, any other test that waits minutes on real timers; list in Notes) run in their own stream, `make lab-test-long`, which runs alongside the default stream and never blocks it.
- [ ] `make lab-test` runs both streams at once; the default stream alone can run on its own.
- [ ] A budget check fails the default stream if it runs past 15 minutes on the remote runner (the limit and how it's measured documented in lab/README.md).
- [ ] Full-lab wall time before and after, in Notes.

## Notes


## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority)
- 2026-11-18 backlog → in-progress, owner: agent-tp-239
