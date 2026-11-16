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
- [x] The lock covers only choosing and reserving a subnet; containers start outside it (file:line in Notes).
- [x] Lab starts from different tests and runs overlap, shown by a timeline from a lab run's log.
- [x] No two live labs ever get the same subnet: a test starts many labs at once (bounded, within the remote runner's memory) and checks.
- [x] The censor-matrix reference rows that timed out on setup under load pass in 3 full labs in a row on the remote runner, run alongside another lab.
- [x] Full-lab wall time before and after, in Notes.

## Notes
- **Lock scope.** `lab/reservations.go:63` `reserveSubnets`: reads the daemon's subnets first (`docker network ls`/`inspect`, which took up to 12 s under load), then takes the allocation lock (`:69`) only to read the live reservations, pick and record its own, and lets go (`:75`). `lab/lab.go:245` `create` then runs `docker compose up` (`lab/lab.go:282`) outside the lock. The lock is a new file, `subnet-reservations.lock` (`lab/reservations.go:36`), not the `subnets.lock` that labs from before this change hold through their whole compose up: sharing it made new labs wait 4–5 minutes behind other branches' old labs. A subnet one of those takes at the same moment is caught by Docker's overlap check and retried, as before.
- **Reservations.** A file per lab in the lock directory's `reservations/`, created under the lock and kept locked (flock) by the lab's process for the lab's whole life; `Lab.Down` or keeping the lab releases it (`lab/lab.go:297`, `:144`). A file nobody holds the lock of belongs to a dead process and is reclaimed under the allocation lock by the next allocation (`liveReservations`, `lab/reservations.go:120`) and by `labctl down`/`-stale`/`-run` (`reclaimReservations`, called from `downWhere`, `lab/teardown.go:143`). A lab whose process exits while the lab stays up (`make lab-up`, a kept lab) leaves only its networks, which every allocation reads from the daemon.
- **Timeline.** `THINKPOL_LAB_TIMELINE=<file>` makes every lab start append one line: lock wait, lock held, compose up from–to, attempt. Runs sharing the file give one timeline.
- **Overlap, from the timeline of the full lab on 0369d34e** (`THINKPOL_LAB_TIMELINE`): 176 lab starts, 39 from the node phase (labctl gotest) and 137 from the lab tests, two processes. Lock wait at most 251 ms, lock held at most 7 ms, up to 8 compose ups at once, 429 overlapping pairs, 101 of them between a node-phase lab and a lab-test lab. The first lines, by compose-up start:
  ```
  19:12:17.499-19:12:53.156 (35.657s) lock (0s)  gotest-ozev36-f46b0f
  19:12:17.562-19:12:53.115 (35.553s) lock (1ms) gotest-ozev36-5a65e5
  19:12:17.623-19:12:51.039 (33.415s) lock (0s)  gotest-ozev36-2b653b
  19:13:21.820-19:13:53.066 (31.246s) lock (0s)  t-ozev36-testrealityprototype-127906
  19:14:30.758-19:14:53.309 (22.551s) lock (0s)  gotest-ozev36-670f70
  19:16:18.856-19:17:36.145 (1m17.289s) lock (0s) gotest-ozev36-392a29
  19:16:55.365-19:17:40.794 (45.429s) lock (0s)  gotest-ozev36-ee4a1a
  ```
  The other full labs on 02597cb7 look the same (lock wait ≤ 251 ms, hold ≤ 3 ms, 7–9 compose ups at once, 295–500 overlapping pairs). Before, the lock was held through each compose up (10–45 s), and while other branches still run that code it is still held that long under `subnets.lock`.
- **Uniqueness.** `TestConcurrentReservationsNeverShareASubnet`: 30 labs × 2 networks reserving at once from 64 /24s, each creating its networks on a fake daemon only after the lock is free, all alive together: 60 distinct subnets. `TestLabStartsOverlapOnDistinctSubnets` (lab-tagged): 4 real labs of one test start at once, stay up together, and get distinct subnets; it also fails if no two of their compose ups overlapped.
- **Wall time.** Before, rewrite e1efa92a (the baseline run made earlier on this ticket; log read back): 3627 s, the lab phase stopped by its 60 min timeout inside the censor matrix (openvpn-tcp and wireguard reference cells still running), the node phase green. After, on 02597cb7: 3605 s, the lab phase again stopped at 60 min (reality and udp cells running), the node phase green. With `LAB_TIMEOUT=150m`: 4678 s and 4858 s on 02597cb7, 4813 s on 0369d34e (lab phase 4669, 4855, 4810 s). All on a host running two or three other lab runs at once. So the full lab is not faster yet: the lab phase is past 60 min on a loaded host either way. Setup no longer waits on the lock; it now goes to compose up itself (median 74–100 s per lab with 7–9 at once, up to 221 s), to lab-slot waits, and to the matrix's own length (TP-240, TP-241, TP-242).
- **Reference rows, 3 full labs in a row, each beside other lab runs:** `make lab-test LAB_TIMEOUT=150m` on 02597cb7 (twice) and on 0369d34e (after merging rewrite): `TestCensorMatrix` passed every time, reference rows included, with no failed compose up in the matrix. The first two runs failed elsewhere: TestShapingCapture (setup budget used up before its compose up, see Log) and TestBlobDistribution (twice, see Log). The third was green (exit 0). The run before them, with the default 60 min, ended on that timeout with matrix cells still running, so it says nothing about the rows.

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-16 widened: the subnet lock's scope is the cause (owner: lab fixes, top priority)
- 2026-11-16 backlog → in-progress, owner: agent-tp-229
- 2026-11-16 subnets are reserved under a short lock of their own (`lab/reservations.go`), compose up runs outside it; reservations live as long as the lab, a dead owner's are reclaimed by the next allocation and labctl down; `THINKPOL_LAB_TIMELINE` records each start
- 2026-11-16 tests: `TestConcurrentReservationsNeverShareASubnet` (30 labs, 60 /24s, no Docker), `TestReservationOfADeadOwnerIsReclaimed` (a SIGKILLed child's reservation, reclaimed by the next allocation and by labctl down's sweep), lab-tagged `TestLabStartsOverlapOnDistinctSubnets` (4 real labs at once). Mutations, each seen failing then restored: allocation ignoring reservations → the concurrent test finds shared subnets and the dead-owner test gets a live child's subnet; a free reservation file treated as live → nothing reclaimed; the lock held through compose up → 4 labs' compose ups serialized (lock waits 6 s, 14 s, 31 s) and the overlap test fails
- 2026-11-16 the baseline full lab on rewrite e1efa92a (made earlier on this ticket, log read back): 3627 s, lab phase stopped by the 60 min timeout in the censor matrix; node phase green
- 2026-11-16 the first version held the old `subnets.lock` and read the daemon inside it: on a host with other branches' labs, new labs waited 4–5 min behind them, and a `docker network inspect` under load held the lock for 12 s; now the lock is a new file, the daemon is read before it, and a reservation lives as long as its lab
- 2026-11-16 full lab on 02597cb7: 3605 s, lab phase stopped by the 60 min timeout (reality and udp cells running), node phase green; the timeline shows no lock waits and up to 7 compose ups at once
- 2026-11-17 full labs with LAB_TIMEOUT=150m beside other lab runs: 02597cb7 twice (4678 s, 4858 s; the censor matrix passed both times; failed: TestShapingCapture once, TestBlobDistribution twice), then merged rewrite and ran 0369d34e: exit 0, 4813 s. `make lint` and `make test` green on 0369d34e. Lab commit: 0369d34e
- 2026-11-17 out of scope, for follow-ups: (1) `lab.Start` counts the wait for a lab slot against its 10 min setup budget; the slots are shared by every run with the same TMPDIR, so on a busy host a test can time out on setup without having started (TestShapingCapture: compose up killed 13 s in, 9m50s after the test began). (2) TestBlobDistribution (blobs_test.go:113): under load `sha256sum` finds no file on device-a right after "blob fetched" is logged (2 of 4 runs). (3) The lab phase is past 60 min on a loaded host before and after this change. (4) TP-242 moves the lab-harness self-tests, `TestLabStartsOverlapOnDistinctSubnets` among them
