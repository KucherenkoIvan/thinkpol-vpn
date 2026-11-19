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
owner: ""
branch: ""
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

## Log
- 2026-11-19 created in backlog (owner: do 1-2)
