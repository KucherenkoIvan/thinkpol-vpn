---
id: TP-215
title: "Linux DNS: the resolv.conf watch adds IN_MODIFY"
milestone: M3
area: dataplane/dns
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-117]
refs: [RR4, RR5]
owner: ""
branch: ""
---

## Goal
The /etc watch hears a truncating open and every write to /etc/resolv.conf as they happen, not only at the writer's close, which narrows the windows RR5 names (a write into a file renamed into the path, still open when the node reads it) and the one TP-117's R4.2 closed only partly (a change during the read).

## Scope
- Add IN_MODIFY to the watch's mask; a modify event counts as a write in place (it settles), never as a rename.
- Measure the event volume from the node's own writes: they go to the temporary name, which the name filter drops, so they should add none; a rewrite in place (TP-117's fallback) adds one per write.
- Update RR4, RR5 and the dns package doc for what the change closes and what is left.

## Out of scope
- Bind-mounted /etc/resolv.conf events (TP-216).
- The settle's timings.

## Acceptance
- [ ] A test in the lab node where a writer renames a file in and then writes into it while still open: the node waits for the write instead of taking the half-written file; evidence: the test and a mutation (IN_MODIFY removed) that fails it, in the Log.
- [ ] The event count from the node's own rewrites, measured; evidence: the numbers in Notes.
- [ ] RR4, RR5 and doc.go updated; evidence: the diff.
- [ ] `make lint`, `make test` and `make lab-test` pass.

## Notes
- Source: TP-117's Log (round 3 and round 4 "out of scope" lines).

## Log
- 2026-11-14 created in backlog (from TP-117)
