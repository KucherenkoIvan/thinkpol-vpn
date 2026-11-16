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
- **Lock scope.** `lab/reservations.go:63` `reserveSubnets`: reads the daemon's subnets first (`docker network ls`/`inspect`, which took up to 12 s under load), then takes the allocation lock (`:69`) only to read the live reservations, pick and record its own, and lets go (`:75`). `lab/lab.go:245` `create` then runs `docker compose up` (`lab/lab.go:282`) outside the lock. The lock is a new file, `subnet-reservations.lock` (`lab/reservations.go:36`), not the `subnets.lock` that labs from before this change hold through their whole compose up: sharing it made new labs wait 4–5 minutes behind other branches' old labs. A subnet one of those takes at the same moment is caught by Docker's overlap check and retried, as before.
- **Reservations.** A file per lab in the lock directory's `reservations/`, created under the lock and kept locked (flock) by the lab's process for the lab's whole life; `Lab.Down` or keeping the lab releases it (`lab/lab.go:297`, `:144`). A file nobody holds the lock of belongs to a dead process and is reclaimed under the allocation lock by the next allocation (`liveReservations`, `lab/reservations.go:120`) and by `labctl down`/`-stale`/`-run` (`reclaimReservations`, called from `downWhere`, `lab/teardown.go:143`). A lab whose process exits while the lab stays up (`make lab-up`, a kept lab) leaves only its networks, which every allocation reads from the daemon.
- **Timeline.** `THINKPOL_LAB_TIMELINE=<file>` makes every lab start append one line: lock wait, lock held, compose up from–to, attempt. Runs sharing the file give one timeline.

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-16 widened: the subnet lock's scope is the cause (owner: lab fixes, top priority)
- 2026-11-16 backlog → in-progress, owner: agent-tp-229
- 2026-11-16 subnets are reserved under a short lock of their own (`lab/reservations.go`), compose up runs outside it; reservations live as long as the lab, a dead owner's are reclaimed by the next allocation and labctl down; `THINKPOL_LAB_TIMELINE` records each start
- 2026-11-16 tests: `TestConcurrentReservationsNeverShareASubnet` (30 labs, 60 /24s, no Docker), `TestReservationOfADeadOwnerIsReclaimed` (a SIGKILLed child's reservation, reclaimed by the next allocation and by labctl down's sweep), lab-tagged `TestLabStartsOverlapOnDistinctSubnets` (4 real labs at once). Mutations, each seen failing then restored: allocation ignoring reservations → the concurrent test finds shared subnets and the dead-owner test gets a live child's subnet; a free reservation file treated as live → nothing reclaimed; the lock held through compose up → 4 labs' compose ups serialized (lock waits 6 s, 14 s, 31 s) and the overlap test fails
