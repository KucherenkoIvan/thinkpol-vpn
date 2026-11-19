---
id: TP-269
title: "Node-phase packages reuse pooled node labs"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-269"
branch: "tp-269-node-phase-pool"
---

## Goal
A cold node phase still runs ~23 packages in a node, each in a freshly started lab (a lab start takes a median 10–40 s under load, plus slot waits), so a cold full lab takes ~16 minutes against the 15-minute budget (warm: 12–15 minutes). The node phase's packages should share labs, one package after another, with the verified reset the `lab/` tests' pools use (TP-261), so a cold node phase starts a handful of labs instead of one per package.

## Scope
- One pool of node labs (`GoTestTopology`) shared by the node phase's packages within a run: a package takes an idle lab, or starts one while the run has fewer than it may run at once.
- After a package, its lab is reset and checked (`Lab.Reset`, lab/snapshot.go) before the next package gets it; a failed check or a failed package retires the lab (torn down: a node lab is never kept, `THINKPOL_LAB_KEEP` or not).
- Packages whose tests change state the snapshot doesn't read (TP-261's "not read" list: e.g. systemd, sysctls outside `net.*`, `/usr`, `/dev`) keep fresh labs, decided per package with a reason, by a marker file as TP-266's `hosttests_test.go` is.
- TP-243's cache semantics unchanged: a package's cache key doesn't name the lab it ran in; reuse must not change it (or, if the image/node identity is in the key, say how it stays stable).
- lab/README.md ("Tests that run inside a node", "Pools") and the package doc describe it.

## Out of scope
- The `lab/` tests' own pools (TP-261), test order and `-parallel` (TP-268), fewer containers per lab test (TP-242), the cache itself (TP-243).

## Acceptance
- [x] Node-phase lab starts on a cold run before/after, in Notes (target: at least halved). 24 → 12 for 24 packages, 0 retired, in every cold run: the node phase alone, and five full labs (Measurements).
- [ ] Cold full lab wall and default stream before/after, in Notes (target: default stream within 15 min). In Notes, but the target isn't met by this ticket: alone on the lab slots, before 801 s (default 13m22s, passed) against after 822 s (13m42s, passed) and 905 s (15m6s, 6 s over). The default stream is bound by the `lab/` tests (TestProberTellsEchoFromNginx 5m25s, the matrix rows 4–4m48s: TP-268's critical path), not the node phase, whose slot waits, starts and tear-downs it cut (Measurements).
- [x] A package that leaves state behind gets the lab retired, not reused (test + mutation). TestHarnessNodePoolRetiresWhatALeftoverSpoils (lab/harness_nodepool_lab_test.go): a package's undoable leftovers (a link, a /tmp file, a process) are undone and logged, the next package gets the same lab back clean; a file changed outside /etc retires the lab and the next package gets a fresh one without the change; a failed package's lab is retired. Mutations in the Log.
- [x] Packages kept on fresh labs listed with why. None, with the audit under "Packages kept on fresh labs"; `freshlab_test.go` marks one when a package needs it.

## Notes
- Baseline: TP-261's full labs on its final head: cold node phase 1002 s (default 16m42s, over budget), warm 713–897 s.

### Design
- `GoTestEach` (lab/gotest.go) runs the node phase's packages in a `nodePool` (lab/gotestpool.go): TP-261's `Pool` of `GoTestTopology()` labs, as many as packages run at once (`-p`), unknown to `lab.Main` and closed when `GoTestEach` returns. A package takes an idle lab or starts one (the run's gate already bounds packages in labs to `-p`, so it never waits for one to come back); after it, the lab is reset and checked (`Lab.Reset`) before the next package gets it. A failed package's lab, or one whose check failed, is torn down (never kept, as the node phase never kept a lab); the next package starts one afresh.
- `Pool` serves a non-test user through `labUser` (Name, Failed, Logf, Errorf: `testing.TB` has them; a package is a `packageUser`); `acquire`, `adopt`, `close` split out of `Acquire`, `start` and `closePools`, so the lab tests' pools work as before.
- What the reset undid goes to the package's output only with `-v` (as `make lab-gotest` runs) or when the check failed: printed always, it made the node phase's output five times longer (1298 lines against 251). Each package's output says which lab it ran in (`lab <project> (pool gotest, use <n>)`), and the run ends with `lab pool gotest: N labs started for M packages, K retired`.
- Cache (TP-243): unchanged. Its key names the image, engine, harness, binary, args, env and the files read, not the lab or its project, so a package run in a pooled lab records and finds the same passes; the test log read back is the package's own, since the reset removes the last package's (`/tmp/thinkpol-gotest.testlog`, a path the clean state lacks).
- `freshlab_test.go` (`lab.FreshLabFile`) marks a package for a lab of its own, with a comment saying what its tests change that the reset doesn't read (`TestFreshLabMarksSayWhat` checks every mark holds only its package clause and such a comment).

### Packages kept on fresh labs: none
Audit of the 24 node packages' tests and the code they run against the reset's "not read" list (lab/README.md, Pools): no test writes a sysctl outside `net.*` (supervisor's `kernel/core_pattern` test asserts the write fails), `/usr`, `/dev`, xattrs or capabilities, tc filters or classes, nexthop objects, txqlen or an alias, a hostname outside its own UTS namespace (the worker's sandbox), or mount options; chmod/chown only under `t.TempDir()`, whose paths the reset removes if left. cgroups (`/sys`, not read) can't change: Docker mounts a gotest node's `/sys/fs/cgroup` read-only (only systemd nodes remount it), so the supervisor runs without them. The tests' own network namespaces go with their last process, or leave a `/run/netns` mount and path, which the reset reads and undoes. A verbose pooled run of all 24 (3b1fa819, `-v`) shows what they leave in the node itself, all undone and checked: `/run/netns` mounts (10 packages), lock files under `/run/thinkpol/netcfg` and `/tmp/thinkpol-lab-locks`, TCP connections in TIME-WAIT (reality 570, censor 253), an orphaned nginx worker (reality), and the supervisor's `net.ipv6.conf.{default,eth0,lo}.accept_ra` left at 2 (clean: 1); 0 labs retired.

### Measurements
- **Cold node phase, before** (13b2c820 = rewrite 389dd581 + this ticket's board commit; `labctl gotest -p 12 -build-p 2 ./...` as `make lab-test` runs it, `LAB_NOCACHE=1`, `THINKPOL_LAB_TIMELINE`, nothing else on the lab slots): 24 packages in labs, **24 lab starts**, passed, wall 162 s; summed: queue 5m43s, slot wait 0, lab start 6m50s, tests 11m5s, teardown 3m21s.
- **Cold node phase, after** (13282682, same command and conditions): **12 lab starts for 24 packages**, 0 retired, passed, wall 176 s; summed: queue 4m12s, slot wait 0.1 s, lab start 4m12s, tests 9m46s, teardown 1m14s. The verbose run (3b1fa819, the machine loaded by another ticket's full lab): 12 starts for 24 packages, 0 retired. The node phase's wall time stays (its longest packages, firewall 1m46s and dns 1m31s of tests, bound it); what it saves is 12 container starts and tear-downs, which the lab's Docker (18–20 container starts a minute) shares with the `lab/` tests.
- **Cold full lab, alone on the lab slots** (`LAB_NOCACHE=1 make lab-test` with `THINKPOL_LAB_TIMELINE`; no other full lab ran, the Docker lock had no other holder at any check, once a minute; harness phase cached in all three, each on its own harness hash's earlier pass):
  - before, 13b2c820: passed, wall 801 s, default stream 13m22s of 15m, long 3m24s; 50 lab starts, 24 of them the node phase's; node phase summed: queue 13m37s, slot wait 31m13s, lab start 9m21s, tests 11m11s, teardown 5m0s.
  - after, dcffc452 (code as a93646e5): passed, wall 822 s, default 13m42s, long 3m20s; 39 lab starts, 12 the node phase's (`lab pool gotest: 12 labs started for 24 packages, 0 retired`); node phase summed: queue 9m58s, slot wait 4m30s, lab start 5m14s, tests 10m13s, teardown 1m14s.
  - after again, dcffc452: tests passed, OVER BUDGET by 6 s, wall 905 s, default 15m6s, long 3m17s; 39 lab starts, 12 the node phase's, 0 retired; node phase summed: queue 9m5s, slot wait 4m28s, lab start 5m30s, tests 10m13s, teardown 1m28s. Slowest: TestProberTellsEchoFromNginx 5m25s, TestCensorMatrix rows 3m55s–4m48s, TestM0/underlay=ipv6 3m48s.
  - So the node phase now waits a seventh as long for slots and starts half the labs, but the default stream's wall is the `lab/` tests' (TP-268's critical path): it didn't move.
- **Cold full labs beside another full lab** (another ticket's `make lab-test` ran the whole time; timing proves nothing, the slots shared by two runs): bf0cf142, harness run: every lab test passed but TestHarnessNodePoolRetiresWhatALeftoverSpoils, which gave up on a lab slot after its own 15-minute bound (fixed in a93646e5: it waits as the lab's budget does), default 42m18s; a93646e5, harness run: passed, default 27m19s, wall 1639 s; dcffc452: passed, default 26m1s, wall 1562 s. Node pool 12 starts for 24 packages, 0 retired, in each.

## Review findings
- [ ] R1.1 (should-fix) Near the end of the node phase, pooled labs sat idle holding slots (an idle lab goes only after ≥15 s, and only while a start waits) until `GoTestEach` returned, where a fresh lab freed its slot when its package ended: those slots are what the `lab/` tests wait for. Fix: the pool counts the packages that may still take a lab (`Pool.countTakers`; a take counts one out, `skip` one that won't take any: served from the cache, nothing to build, stopped at the gates) and keeps no more labs idle than that, tearing the longest idle down first, none once no package is left (lab/pool.go `trimIdle`). Test: TestNodePoolTearsDownWhatNoPackageTakes; confirmed by the full lab's timeline (pool-down lines against the `lab/` tests' slot waits).
- [ ] R1.2 (should-fix) A pooled node lab whose tear-down failed at idle or close only printed to stderr; a fresh lab's failed tear-down failed the node phase. Fix: `Pool.teardown` records the error, `Pool.close` returns it, `GoTestEach` joins it into its error; `closePools` (the `lab/` tests' pools) prints it to its writer as before. Test: TestNodePoolTearsDownWhatNoPackageTakes (a fake lab's Down failing).
- [ ] R1.3 (should-fix, doc) `-times` (labctl's usage) and the README's budget report and "How much runs at once": a lab start is charged only to the package that started the lab; a package that reused one is charged its reset as teardown.
- [ ] R1.4 (tests) TestNodePoolOutput: a package's output, not verbose, says why its lab's reset didn't hold, and what a reset that held undid only with -v; the harness test runs two packages not verbose and checks the same. TestFreshLabPackageSkipsThePool: a FreshLab package runs in a lab of its own and never reaches the pool (`packageRun`'s pool and fresh runner injected).
- [ ] R1.5 (nits) Scope's "kept with THINKPOL_LAB_KEEP" fixed (a node lab is never kept); `freshRun` → `labRun`, `nodePool.started` → `seq`, `nodePoolProject(checkout, run, i)`; `res.labErr = errors.Join(u.errs...)`; pool messages "it failed" and "the users that had the lab before it"; SysV IPC (`ipcs`) in the snapshot's not-read list (lab/snapshot.go, README).

## Log
- 2026-11-19 created in backlog (owner: do 1-2)
- 2026-11-19 backlog → in-progress, owner: agent-tp-269
- 2026-11-19 baseline cold node phase on 13b2c820 (24 starts, 162 s); built the node pool: `GoTestEach` (lab/gotest.go ~300) runs packages through `nodePool` (lab/gotestpool.go), TP-261's `Pool` with a `labUser` in place of `testing.TB` (lab/pool.go ~71) and `acquire`/`adopt`/`close` split out; `FreshLabFile` (lab/gotest.go ~40) for a package that needs a lab of its own; the reset's log printed only with -v or a failed check; README ("Tests that run inside a node", "Pools", "How much runs at once"), doc.go and labctl's usage
- 2026-11-19 mutations (each restored after; lab ones in a scratch worktree, never pushed): `nodePool.goTest` reports every package as passed (a failed package's lab handed on) → TestHarnessNodePoolRetiresWhatALeftoverSpoils fails ("a failed package's lab … was handed on"); `giveBack` ignores the reset's error → it fails ("a lab whose check failed was handed on", 1 line changed); `ListGoPackages` drops the mark → TestListGoPackagesFindsTheFreshLabMark fails; the mark lint without the declarations check, or taking a blank comment for a reason → TestFreshLabMarkProblem fails. Not mutation-checked: `inLab` choosing a fresh lab for a marked package (no package is marked, and a test of it needs a lab per package)
- 2026-11-19 runs: cold node phase on 13282682 12 starts (176 s); verbose on 3b1fa819 12 starts, what each package leaves in Notes; TestHarnessNodePoolRetiresWhatALeftoverSpoils passed on 3b1fa819 and a93646e5; make lint and make test passed on a93646e5 (Linux); full labs: beside another full lab on bf0cf142 (harness test's own bound), a93646e5, dcffc452; alone on 13b2c820 (before) and twice on dcffc452 (after): Notes
- 2026-11-20 not verified: the default stream within 15 minutes (bound by the `lab/` tests, TP-268); a marked package's fresh lab (none marked)
- 2026-11-20 out of scope: internal/agent/supervisor's tests leave `net.ipv6.conf.{default,eth0,lo}.accept_ra` at 2 (clean: 1) after their forwarding is put back; internal/dataplane/transport/reality's tests leave an orphaned nginx worker; on a Mac, lab/labctl's TestGotestSkipAndTimes and TestGotestRunsNodelessPackagesOnTheHost fail on the base too (a temp dir under /private/var is read through a doubled /private), they pass on Linux; the reset's log says "the tests that had the lab before it" for packages too
- 2026-11-20 in-progress → review
