---
id: TP-262
title: "A lab starts faster"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-262"
branch: "tp-262-faster-lab-start"
---

## Goal
`docker compose up` takes 46–78 s median per lab on the remote runner, longer under load. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-19 on rewrite cb0348d6 with every lab-speed ticket merged: 23m12s cold and 23m8s with the node phase fully cached; all tests passed; the lab/ package alone took ~22 minutes; lab slot waits median 60–73 s, max 9–11 min; `docker compose up` per lab median 46–78 s; 57–111 lab starts per run.

## Scope
- Measure where a lab start's time goes: image layers, container create, network create, the `--wait` health checks, the node's own boot.
- Cut it (e.g. a lighter node image, health checks that watch state instead of polling intervals, pre-created networks, parallel container start), keeping every lab test's claims.

## Acceptance
- [x] Breakdown of a lab start before and after, in Notes.
- [ ] Median lab start halved on the remote runner (timeline). Moved to TP-261 (lab reuse): `docker compose up` is 85–98% of a start and, under load, is bound by the disk under the Docker daemon, so the lever is fewer Docker objects per run, not a faster start of each. Measured here: −18% median in one interleaved 4-node A/B, 10 starts per side (12.77 → 10.45 s). The before/after breakdown table compares sets run under different loads: its differences are load noise, not the change's effect (see Notes, "Not halved").
- [x] No lab test changes what it proves.

## Notes
**How it was measured.** `TestLabStartTimes` (new, skips unless `THINKPOL_LAB_START_TIMES=n`) starts n labs of each size one after another under the normal lab slots: 1 node (the node phase's), 4 (a censor matrix row's: router, device-a, server-1, camouflage) and 7 (`lab.Upstream()`). It logs each start's steps and, from a live `docker events` stream, when `docker compose up` created the networks and created and started the containers. The timeline (`THINKPOL_LAB_TIMELINE`) now has a `start` line per lab (from the slot to sealed: `create` = subnets + compose up, `inspect`, `bridges`, `seal`), a `down` line per tear-down, and a `subnet-read` line (TP-267). Before = 49693be1 (the instrumentation only, on rewrite 42945fdd); after = 1bfbe69c. 10 starts per size each, on the remote runner. Load came from the other tickets' labs and varied between sets. For the 4-node size an interleaved A/B (before 5, after 5, before 5, after 5, matrix-row only) keeps both sides under the same load.

**Breakdown, medians in seconds (min–max)**

| step | 1 node before | after | 4 nodes before | after | 7 nodes before | after |
|---|---|---|---|---|---|---|
| load (1-min avg) | ~8–15, few labs | ~8–17 | 10–25 | 6–17 | 10–23 | 10–23 |
| slot → sealed | 4.03 (3.05–40.8) | 3.42 (2.48–16.8) | 88.4 (10.2–153) | 10.9 (9.6–87.4) | 122 (17.9–229) | 108 (17.7–139) |
| slot → lock: subnet read (TP-267) | 0.09 (–34.4) | 0.00 (all) | 2.62 (–37.2) | 0.00 (all) | 1.01 (–48.6) | 0.00 (all) |
| subnet read before the slot | – | 0.14 (–1.4) | – | 0.20 (–4.0) | – | 2.52 (–5.0) |
| docker compose up | 3.52 | 2.82 | 77.5 | 10.0 | 108 | 105 |
| inspect | 0.10 | 0.12 | 1.06 (–5.9) | 0.19 (–3.1) | 0.84 (–4.5) | 1.53 (–4.6) |
| bridges | 0.10 | 0.11 | 0.58 (–1.6) | 0.25 | 0.44 | 0.21 |
| seal | 0.21 | 0.24 | 0.92 | 0.57 | 0.92 | 0.74 |
| tear-down (slot still held) | 1.87 | 2.48 | 23.0 | 11.3 | 30.3 | 35.0 |

Interleaved A/B, 4 nodes, 10 starts each side, load 3–25 falling during the run: slot → sealed **12.77 → 10.45** (−18%); compose up 11.12 → 9.86; inspect 0.16 → 0.11; bridges 0.29 → 0.13; seal 0.34 → 0.32; slot → lock 0.06 → 0.00.

Inside `docker compose up` (Docker's events, medians):
- 1 node, idle: networks at 0.43–0.49 s; container created at 1.9–2.1 s; started at 2.9–3.1 s. Before, up returned 0.5 s after the start: `--wait` polling.
- 4 nodes, under load (before): networks at 5.2 s; containers created at 27.6–29.2 s, all of a lab's within about 1.5 s of each other, as if they waited on one thing; started at 42–79 s, one after another.
- 7 nodes, under load: networks at 3.6–5.7 s; created at 15–33 s; started at 39–116 s.

**Where the time goes.** `docker compose up` is 85–90% of a lab's start at every size and load. Under load it is 10–20 times its idle time. The disk that holds Docker sat at about 90% utilisation, with about 120 small writes and 30 flushes a second, while the machine created about 20 containers a minute. Every Docker object a lab makes waits on that disk: networks, containers, endpoints (one per node per network, joined one after another on a shared network), and their removal. Network reads (inspect) wait behind the network writes. What the harness itself adds is small at the median (0.4–1 s idle, 2–6 s under load), but it reached about 50 s at worst, nearly all of it TP-267's subnet read.

**What changed** (all in `lab/`; no topology, node, image or test changed):
- The daemon's subnets are read before the lab slot, not holding it (`up`). The first try reserves against that read plus the live reservations, and a try after a Docker overlap reads afresh (`Lab.create`) (TP-267).
- The read inspects networks in chunks of 4 at once. It takes the CLI's output for the networks it found instead of inspecting one by one whenever one vanished, and lab starts of one process share a read that is running (`usedSubnetsVia`, `sharedRead`).
- The lab's networks are inspected in one call (`inspect`); their bridges are learned at once (`learnBridges`).
- `docker compose up` runs without `--wait`, which polled every 0.5 s after the containers had started. A node that died at once fails the sealing's `docker exec` instead.
- A start no longer runs `docker compose down` for a leftover lab that doesn't exist (`downProject`).

**Not halved.** The one load-matched measurement is the A/B: the median 4-node start went from 12.8 to 10.5 s (−18%). The breakdown table's before and after sets ran under different loads, so its differences (1 node 4.0 → 3.4 s, 4 nodes 88 → 11 s) are mostly load, not the change. Under heavy load the subnet read's 20–50 s tail is gone from the slot. The rest is Docker's own work per object, which no harness change shortens, so halving needs fewer Docker objects per lab or per run:
- fewer containers (TP-242);
- labs reused (TP-261);
- in-node labs without a Docker network: one network, one endpoint and the subnet read fewer per node-phase lab, the most common lab. Not done here: `internal/agent/supervisor`'s isolation test sends to the node's own eth0 addresses (`crossTargets`), so it would need a stand-in uplink, or it proves less.
- tear-down (2–35 s median) holds the slot and is the same kind of Docker work.
**Full lab** (`make lab-test` on 289bd442, alongside another ticket's full lab and a node-phase run): every test passed, RESULTS.md assembled; wall 2804 s; long stream 8m51s, default stream 46m43s, over its 15m budget under that load. Its slowest were `TestHarnessAnotherRunFromTheCheckoutBuildsItsOwnBinaries` (16m19s) and the matrix rows (12–14.5 min each). Its timeline (111 starts): slot → sealed medians 27.7 s (1 node, 54 starts), 80 s (3), 96 s (4, 29 starts), 120 s (5); `docker compose up` 91–98% of each; slot → lock 0.00 s in every start; the subnet read before the slot 0.5–3.3 s median, 10.6 s max.

## Review findings
Review round 1 (two reviewers): subnet safety holds; dropping `--wait` and skipping `docker compose down` for a lab that doesn't exist are fine. Fix these, then merge.
- [x] R1.1 (should-fix) lab/subnets.go: `usedSubnetsVia` started one docker CLI per 4 networks with no cap; with up to 12 test processes at once that is hundreds of docker CLIs on a daemon whose disk is already the bottleneck. Cap the fan-out (a semaphore of 8 per read).
- [x] R1.2 (should-fix) lab/lab.go: no test covered "a retry after an overlap reads afresh" (reusing the pre-slot read passed every test); add it with a mutation. A stale pre-slot read (as old as the slot wait) that fills the pool failed with "no free /24 left" and was never retried on fresh data: on the first try, treat a full pool like an overlap (read afresh and retry), via a sentinel error.
- [x] R1.3 (nits) the before-slot timeout message omitted the subnet read; `Lab.started` exists only for TestLabStartTimes: comment it as test instrumentation; TestLabStartTimes matches a lab's events by the exact Compose project label (and network names), not a name prefix; a unit test for the single network-inspect parsing.
- [x] R1.4 (ticket) the "halved" box: unticked, with what was measured stated honestly (−18% median, one interleaved 4-node A/B, 10 starts per side; the before/after table is load noise), moved to TP-261 (lab reuse) with the reason.
- [x] R1.5 (tickets) TP-267: its boxes are ticked from this branch's evidence; it moves with TP-262.

## Log
- 2026-11-19 created in backlog (full-lab measurement on rewrite cb0348d6)
- 2026-11-19 backlog → in-progress, owner: agent-tp-262
- 2026-11-19 TP-267 folded in (orchestrator): the slot-to-lock gap is the read of the daemon's subnets; moving it before the slot
- 2026-11-19 measured: TestLabStartTimes (new) and the timeline's start/down/subnet-read lines; baseline at 49693be1, 10 starts each of 1, 4 and 7 nodes; after at 1bfbe69c; interleaved A/B for 4 nodes (before 49693be1 / after 1bfbe69c)
- 2026-11-19 done: subnet read before the slot (TP-267), chunked and shared, one inspect when networks vanished; one network inspect per lab; bridges at once; compose up without --wait; no compose down for a leftover that doesn't exist
- 2026-11-19 mutations (each failed its test, then restored): chunk outputs dropped (TestUsedSubnetsReadsEveryChunk); a non-not-found error line ignored (TestUsedSubnetsFailsClosed); never join a running read, and join regardless of notBefore (TestSharedReadJoinsARunningRead); "-" for an unreached step dropped (TestTimelineStartAndDownLines); subnet-read line's separator (TestTimelineStartAndDownLines); one-by-one inspect restored (TestUsedSubnetsSkipsNetworksRemovedAfterTheList's single-inspect check); compose down for a missing project (TestDownProjectSkipsComposeWithNothingToRemove)
- 2026-11-19 make lint, make test green on 289bd442 (merge of rewrite 35b02ca7, TP-260); make lab-harness pass on 1bfbe69c; lab-gotest PKG=./lab RUN=TestSmoke|TestM0|TestNoIPv6LeavesAroundTheTunnel|TestCensorSeesUpstream|TestProberTellsEchoFromNginx|TestServiceUnderSystemd pass on 1bfbe69c; lab-gotest PKG=./internal/dataplane/tun/... ./internal/agent/supervisor/... pass, uncached
- 2026-11-19 full make lab-test on 289bd442: tests passed, wall 2804 s, default stream 46m43s over its 15m budget (another full lab ran at the same time); slot → lock 0.00 s in all 111 starts
- 2026-11-19 not verified: the halving (not reached, see Notes); load-matched comparison for 1 and 7 nodes (only the 4-node A/B is interleaved)
- 2026-11-19 out of scope, for the board: in-node labs without a Docker network (needs a stand-in uplink for supervisor's isolation test); tear-down holds the slot 2–35 s median; TestHarnessAnotherRunFromTheCheckoutBuildsItsOwnBinaries took 16m19s in the full lab
- 2026-11-19 merged rewrite 02574d94 (TP-258: lab tests and the local API, no harness file): make lint, make test green on b1676c35; the full lab above is on 289bd442, before that merge
- 2026-11-19 in-progress → review (with TP-267)
- 2026-11-19 review round 1: fix R1.1–R1.5, merge
- 2026-11-19 R1.1–R1.3 in b8eb0ca7: at most 8 subnet-read inspects in flight (`inspectsAtOnce`); `createTries` (create's loop) reads afresh after an overlap and, on the first try, after a full pool (`errNoFreeSubnet`); `parseGateways`; before-slot timeout message names the subnet read; `Lab.started` commented as TestLabStartTimes' instrumentation; TestLabStartTimes matches events by network name and the Compose project label. New tests TestUsedSubnetsCapsInspectsAtOnce, TestCreateTriesReadAfresh (overlap, pool full), TestParseGateways
- 2026-11-19 mutations (scratch checkout, never pushed), each failed its test, then restored: semaphore removed (TestUsedSubnetsCapsInspectsAtOnce: 32 at once); a retry reusing the pre-slot read (TestCreateTriesReadAfresh: overlap 5 ups, pool full); the full-pool retry dropped (TestCreateTriesReadAfresh/pool_full); the gateway's "/len" cut dropped (TestParseGateways)
- 2026-11-19 on b8eb0ca7: make lint, make test green; make lab-harness pass (150 s); lab-gotest PKG=./lab RUN=TestSmoke|TestM0 pass. Docker CLIs started from this checkout's run, sampled during both: at most 6 (harness) and 4 (smoke) subnet-read inspects at once, 11 and 17 docker CLIs in all; the cap of 8 never bound there (the daemon had too few networks for more than 8 chunks), the unit test shows it binding (32 chunks, 8 at once)
- 2026-11-19 review → done (merged; TP-262's 'halved' box moved to TP-261)
