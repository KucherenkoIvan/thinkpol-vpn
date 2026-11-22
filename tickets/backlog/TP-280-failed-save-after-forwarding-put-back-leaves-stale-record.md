---
id: TP-280
title: "A failed save after putting forwarding back leaves a stale record"
milestone: later
area: agent/supervisor
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-276]
refs: []
owner: ""
branch: ""
---

## Goal
Once the supervisor has put a forwarding switch back, no record says that switch is still its own, even when the save after the put-back fails, so a successor never adopts (and turns off) forwarding someone else turned on later.

## Scope
- `restoreFamily` (internal/agent/supervisor/forwarding.go) writes the switch back and drops the family; the save that follows (`ensure`'s, or `restore`'s at Close) can fail (e.g. /run full). The record on disk then still has Main.Written "1" for a switch that is now off.
- Someone who turns that switch on later (a container runtime) is adopted by the next start, as if the supervisor had left it on: confined by its tables and turned off when no space needs it or at Close.
- Fix: record the put-back before it is made (e.g. save the family with Main.Written empty, keeping the accept_ra entries, before writing the switch back), or remove the record before the write when nothing else is left; a failed save then fails the put-back with the switch untouched, as a failed save fails `enable` since TP-276.

## Out of scope
- The window before the switch is written (TP-276, accepted there).

## Acceptance
- [ ] A test: the save after a put-back fails, someone else turns the switch on, and a successor neither adopts it nor turns it off.
- [ ] Every new test mutation-checked, mutations in the Log.
- [ ] `make lab-gotest PKG=./internal/agent/supervisor/...` green.

## Notes
- Found in TP-276's review (2026-11-22). Pre-existing (the record has always been saved after the put-back, not before), and rare: it needs a failed save on a tmpfs, then someone else turning that switch on before the next start.

## Log
- 2026-11-22 created in backlog (from TP-276's review)
