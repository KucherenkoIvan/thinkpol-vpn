---
id: TP-191
title: "Lab: reap labs of interrupted runs"
milestone: later
area: lab
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
An interrupted lab run doesn't leave its lab behind until `make lab-down`, and repeated interrupted runs don't use up the lab subnet pool.

## Scope
- A run stopped by Ctrl-C or `-timeout` leaves its containers and networks. Each holds a /24 from the lab subnet pool (lab/README.md, "Isolation and safety"), so repeated interrupted runs can exhaust it.
- Before a test or gotest lab is created, find test and gotest labs whose run is no longer alive and remove them. Only `tplab-*` resources, and never a lab whose run is still alive.

## Out of scope
- Labs started by hand with `make lab-up`: they stay until `make lab-down`.

## Acceptance
- [ ] a test: a lab whose run is gone is reaped by the next run; a lab whose run is alive is kept
- [ ] lab/README.md says when labs are reaped
- [ ] `make lint`, `make test` pass

## Notes
- Found in TP-146's round-1 review, 2026-11-07.

## Log
- 2026-11-07 created in backlog
