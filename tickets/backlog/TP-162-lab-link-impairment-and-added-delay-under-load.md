---
id: TP-162
title: "Lab: link impairment (loss, delay, jitter) and an added-delay-under-load measurement"
milestone: M2
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-089]
refs: [PRD#non-functional-requirements]
owner: ""
branch: ""
---

## Goal
The lab can impair a link with netem (loss, delay, jitter, reordering), per link or for a whole topology. `make lab-perf`, or whatever replaces it, reports p95 added one-way delay per hop under a saturating flow, alongside throughput and loss, and can gate on it. Then the PRD's Performance requirement can be checked in the lab, as the PRD says it should be.

## Scope
- PRD.md "Non-functional requirements", Performance: through a two-hop chain on 1-vCPU nodes, video calls without noticeable degradation, ≥ 50 Mbit/s, and at most 10 ms of overhead per hop beyond network RTT, "to validate in the lab". Two things block that today:
  - the lab has no link impairment: every lab network is a clean bridge, so nothing runs over loss, delay or jitter;
  - `make lab-perf` (Makefile `LAB_PERF_PKGS`, lab/README.md "Performance gates") gates only throughput and loss (`TestSharedListenerThroughput`) and never measures added delay.
- An impairment API on lab topologies or nodes: netem loss, delay, jitter and reordering on one link (a node's interface on a network) or on every link of a topology. It is applied inside the lab containers and removed when the lab goes, like everything else a lab creates.
- An added-delay measurement under load: one flow saturates the path through each hop while a low-rate probe measures one-way delay. The report gives p50 and p95 added delay per hop (over the same path without the tunnel) next to throughput and loss.
- A gate on it in `make lab-perf`, following that section's rules (measure, two retries on a miss, median of three). The threshold is a parameter. This ticket doesn't choose the NFR's number.
- lab/README.md documents the impairment API and the new measurement, with its conventions ("Tests under load", "Performance gates").

## Out of scope
- Changing transports or adding AQM or queue management anywhere on the path: this ticket measures and decides nothing.
- Restating the Performance requirement (what "overhead" means under load, the per-hop number): an owner decision, made once there are numbers.
- The resource-footprint run and the README system requirements: TP-067.

## Acceptance
- [ ] a lab test impairs one link with netem (loss, delay, jitter, reordering), sees the impairment on that link only, and sees it gone after the lab tears down
- [ ] the same impairment can be set on every link of a topology in one call
- [ ] `make lab-perf` reports p50 and p95 added one-way delay per hop under a saturating flow, with throughput and loss, for a two-hop chain
- [ ] a gate on p95 added delay per hop, threshold as a parameter, run with `make lab-perf`'s retry-and-median rule
- [ ] lab/README.md describes both
- [ ] `make lint`, `make test`, `make lab-test` pass; `make lab-perf` runs (its numbers recorded in Notes)

## Notes
- Source: a check of the PRD's Performance requirement against the lab, 2026-10-31: the requirement says "to validate in the lab", and nothing in the lab can do that yet.
- An earlier informal device measurement (TP-067 Notes, device run 4: an exit in a container capped at 0.75 CPU, download at that cap) saw about 170 ms of extra queueing delay in front of the saturated exit, against an idle tunnel RTT 21 ms over direct. That is far from 10 ms per hop, but it was one run on a real network under a CPU limit, not the lab method. This ticket provides the lab method.
- Builds on TP-089's topology work: `lab.Upstream()` (on TP-089's branch until it merges) adds a node on a network of its own behind the router. Use the topology API as it stands then, and follow lab/README.md's conventions for nodes, networks and perf tests.

## Log
- 2026-10-31 created in backlog (PRD Performance requirement checked against the lab)
