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
- After a package, its lab is reset and checked (`Lab.Reset`, lab/snapshot.go) before the next package gets it; a failed check or a failed package retires the lab (torn down, or kept with `THINKPOL_LAB_KEEP`).
- Packages whose tests change state the snapshot doesn't read (TP-261's "not read" list: e.g. systemd, sysctls outside `net.*`, `/usr`, `/dev`) keep fresh labs, decided per package with a reason, by a marker file as TP-266's `hosttests_test.go` is.
- TP-243's cache semantics unchanged: a package's cache key doesn't name the lab it ran in; reuse must not change it (or, if the image/node identity is in the key, say how it stays stable).
- lab/README.md ("Tests that run inside a node", "Pools") and the package doc describe it.

## Out of scope
- The `lab/` tests' own pools (TP-261), test order and `-parallel` (TP-268), fewer containers per lab test (TP-242), the cache itself (TP-243).

## Acceptance
- [ ] Node-phase lab starts on a cold run before/after, in Notes (target: at least halved).
- [ ] Cold full lab wall and default stream before/after, in Notes (target: default stream within 15 min).
- [ ] A package that leaves state behind gets the lab retired, not reused (test + mutation).
- [ ] Packages kept on fresh labs listed with why.

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

## Log
- 2026-11-19 created in backlog (owner: do 1-2)
- 2026-11-19 backlog → in-progress, owner: agent-tp-269
