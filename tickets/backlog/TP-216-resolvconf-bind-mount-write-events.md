---
id: TP-216
title: "Linux DNS: does a write to a bind-mounted resolv.conf raise an event on the /etc watch?"
milestone: M3
area: dataplane/dns
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-117]
refs: [RR4]
owner: ""
branch: ""
---

## Goal
RR4's suspicion is settled: whether a write in place to a bind-mounted /etc/resolv.conf (as in containers) raises any event the node's /etc directory watch sees.

## Scope
- In a lab container with /etc/resolv.conf bind-mounted from another file, write it in place (truncate and write, append) and record which inotify events, if any, reach a watch on /etc.
- If none do, the 2 s poll is the only signal there: say so in RR4 and the dns package doc instead of the suspicion.

## Out of scope
- Watching the bind mount's source (the node can't see it from inside a container).

## Acceptance
- [ ] The events seen (or none) for each kind of write, from a lab test or a recorded run; evidence: the test or its output in Notes.
- [ ] RR4 and doc.go state the result, not a suspicion; evidence: the diff.
- [ ] `make lint`, `make test` pass, and the lab test if one was added.

## Notes
- Source: TP-117's Log ("not verified" after round 4) and R4.3.

## Log
- 2026-11-14 created in backlog (from TP-117)
