---
id: TP-254
title: "Lab tests run as many at once as the machine's lab slots allow"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-254"
branch: "tp-254-lab-parallel-follows-slots"
---

## Goal
A full `make lab-test` runs as many labs at once as the machine's lab-slot cap allows, so the default stream gets closer to the owner's 15-minute target (2026-11-16). TP-247 found (2026-11-19) that the `lab/` test binary runs with Go's default `-test.parallel` (GOMAXPROCS), below the 12-lab slot cap, so the matrix's row labs and the other parallel lab tests queue behind each other. The node phase runs `labctl gotest -p $(LAB_P)`, and the machine's CPU-slot wrapper sets `LAB_P` to the job's CPU weight (3 for a full lab), so at most 3 node packages run at once although each mostly waits on containers. The owner's rule (2026-11-16): weights are machine-agnostic, and how much work runs at a time is decided by the machine's configuration; for labs, the lab-slot cap is that configuration. The full lab's default stream took 34m12s, with lab starts waiting up to ~3 min for a slot.

## Scope
- The lab streams' test binaries (`lab/` and the other `./lab/...` packages, both streams, the harness phase) run with `-test.parallel` equal to the machine's lab-slot cap: the same `THINKPOL_LAB_MAX_LABS` the slots read (default 12), through one Make variable, so a machine sets it in its environment.
- The node phase's `labctl gotest` runs as many packages at once as that cap; `LAB_P` keeps bounding only the CPU-bound part, the package test builds.
- lab/README.md says how concurrency is set.

## Out of scope
- The slot cap itself (`THINKPOL_LAB_MAX_LABS`, its default).
- `make lab-gotest`'s concurrency.

## Acceptance
- [ ] lab/ and node-phase concurrency follow the lab-slot cap (Makefile, README).
- [ ] Full-lab default stream before and after, in Notes (budget report: wall, slot waits, slowest tests).
- [ ] No new failures from the higher concurrency (full lab green, or failures shown unrelated by targeted re-runs).

## Notes

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 backlog → in-progress, owner: agent-tp-254
