---
id: TP-279
title: "A server reports its map applied while its first apply is still opening listeners"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-279
branch: tp-279-applied-means-serving
---

## Goal
A server's status, and its "map applied" log line, say the map is applied only once every listener of it serves, so a caller waiting on them (the lab's `mapApplied`, an operator) knows the server is reachable.

## Scope
- A server's status reads the new map version, not retrying, while its first apply still opens the listeners (and, on reality, checks the target), and the "map applied" line (`internal/agent/node.go:1007`) comes before the workers know the listeners (TP-278).
- So the lab's `mapApplied` helper (`lab/nodestatus_test.go:228`) passes early, and the censor matrix starts device-a before the server listens. This hid TP-230's bug (a listener that never opened, retried every 5 s) from the matrix's reality setup.
- Either status and the log line come only after every listener serves, or status gets a separate "serving" field; the lab waits on it.

## Out of scope
- The supervisor serving a listener before its workers know it: TP-278 (this ticket's "serves" means after that fix, or must include it).

## Acceptance
- [ ] A server's status and its "map applied" line come only after every listener serves (or a separate "serving" field says so), with a test that holds a listener's open and sees neither before it ends.
- [ ] The lab waits on it: `mapApplied` (or its replacement) passes only once the server serves, and the matrix's setups use it.

## Notes
- Found in TP-230 (2026-11-22).
- Built on TP-278 (branch `tp-279-applied-means-serving` starts from TP-278's): merge TP-278 first. Not in `depends_on`, since the board allows backlog → in-progress only once every dependency is done.

## Log
- 2026-11-22 created in backlog (from TP-230's review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-279
