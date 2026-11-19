---
id: TP-265
title: "The node phase reports a package's slot wait apart from its run time"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
A package's time in the node phase (`GoTestResult.Elapsed`, lab/gotest.go `inLab`) starts when its lab starts, so it includes the wait for a lab slot, `docker compose up` and teardown. In TP-263's measurement packettest looked 8.5 minutes slow while its tests take 0 s. Lab-speed work needs to see which part of a package's time is its own.

## Scope
- Time the slot wait, the lab start, the tests and the teardown of each package separately.
- Show the four in the node phase's output and in the budget report.

## Acceptance
- [ ] Node-phase lines and the budget report show slot wait, lab start, tests and teardown separately (test).

## Notes

## Log
- 2026-11-19 created in backlog (TP-263)
