---
id: TP-229
title: "The subnet lock covers only picking a subnet"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-229"
branch: "tp-229-subnet-lock-scope"
---

## Goal
The measured cause of TP-229's setup timeouts and of serialized lab starts: the subnet allocation lock is held through the whole container start-up.

The owner (2026-11-16): a full lab must take at most ~15 minutes on the remote runner; waits only where no watcher can tell, otherwise a sped-up clock; long-wait tests in a separate stream that never blocks others; everything that can run in parallel must. Measured on the remote runner (2026-11-16): the `lab/` package alone took ~46 min; the host-wide subnet allocation lock is held for each lab's whole `docker compose up --wait` (10–45 s per lab), so lab starts are serialized across every run (~92% busy); non-parallel teardown tests add a ~14.5-minute serial prefix before parallel tests resume.

Original report: A full `make lab-test` fails on censor-matrix reference cells (e.g. `TestCensorMatrix/relay-tcp_(reference)/server-hello`, `openvpn-tcp (reference)`) when other labs run on the same host: `docker compose up` is still creating containers at the 600 s limit (one hung with 3 of 7 containers started), or cells wait on the lab's subnet allocation lock. Seen in three branches' full labs on 2026-11-16, each on a loaded host. M2 closes on a green full lab, so this must be fixed or bounded.

## Scope
- Find why compose up stalls (image pulls, network creation, the subnet lock's hold time, container start under CPU pressure), with evidence.
- Make the matrix robust (bounded and honest waits, setup that doesn't hold a shared lock longer than needed, or serialising matrix setup) without hiding a real failure.

## Out of scope

## Acceptance
- [ ] The lock covers only choosing and reserving a subnet; containers start outside it (file:line in Notes).
- [ ] Lab starts from different tests and runs overlap, shown by a timeline from a lab run's log.
- [ ] No two live labs ever get the same subnet: a test starts many labs at once (bounded, within the remote runner's memory) and checks.
- [ ] The censor-matrix reference rows that timed out on setup under load pass in 3 full labs in a row on the remote runner, run alongside another lab.
- [ ] Full-lab wall time before and after, in Notes.

## Notes

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-16 widened: the subnet lock's scope is the cause (owner: lab fixes, top priority)
- 2026-11-16 backlog → in-progress, owner: agent-tp-229
