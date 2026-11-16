---
id: TP-240
title: "The censor matrix runs one lab per transport row"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: L
depends_on: [TP-223]
refs: []
owner: "agent-tp-240"
branch: "tp-240-matrix-lab-per-row"
---

## Goal
The censor matrix costs 9 labs, not 90. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-16: a clean full lab takes 2823 s, and the remote runner's Docker starts only ~18–20 containers a minute, while a run starts 836 containers: the censor matrix 574 of them in 90 labs, each cell in use only 5–30 s.

## Scope
- `TestCensorMatrix` (lab/results_test.go:44) starts one Upstream lab per transport row and runs `off` and then each censored case in it, in sequence.
- Between cells: stop the transport's processes, stop censord and remove its nft and queue tables, flush the router's conntrack, and start a fresh verdict log.
- Then check the reset held: no `censor*` table, no queue rule, no leftover processes or flows.

## Out of scope
- Moving the rhythm cell to the long-wait stream: TP-239.

## Acceptance
- [x] The censor matrix starts ≤ 9 labs. Evidence: `docker events` container starts by Compose project during a targeted `TestCensorMatrix` run on 632ed83a: 9 labs, 63 container starts (see Notes). Not shown in a full lab: targeted runs only until the lab tickets land; the full-lab number comes from the first full lab on rewrite after they do.
- [x] RESULTS.md is identical in verdicts to one made with per-cell labs on matching matrix code. Evidence: a diff of the per-row RESULTS.md from 632ed83a against the per-cell one from TP-229's full lab on 0369d34e, a different commit whose matrix files, lab/censor and lab/censord equal this branch's base: the 90 verdicts are identical (see Log). Not a same-commit comparison.
- [x] A mutant that skips the reset step fails a cell. Evidence: the mutation run's output. (Every cell of the plain-tcp row failed; see Log.)

## Notes
- Saving: ~510 container starts ≈ 28 min of Docker time.
- Do it before or with TP-239 (the long-wait stream moves the rhythm cell out).
- How it works: each row starts one `lab.Upstream()` lab (`startRow`, lab/matrixreset_test.go), starts the camouflage site, clears the router (`censord -reset`) and records every node's state: processes, links, policy rules, nftables tables, bound NFQUEUE queues, and the entries of `/tmp`, `/run` (but `/run/lab`) and `/var/lib`. Every cell sets its transport up afresh; its cleanup (`runCell`, lab/results_test.go) then calls `matrixRow.reset`: kill what still runs, remove the links, rules, tables and files the cell left, `censord -reset` (`censor.ClearRouter`: delete the `censor` table, flush conntrack over ctnetlink, both families; the image has no `conntrack` tool), and `check`: every node equal to its recorded state, no `censor*` table, no queue statement in the router's ruleset, `nf_conntrack_count` 0. A reset that fails makes the cell an error and every later cell of the row an error too.
- The per-cell transport setup needs the reset beyond censord: kernel WireGuard's `ip link add wg4` fails if the last cell's link is still there, and a fresh map space at version 1 needs `/var/lib/thinkpol` gone.
- Container starts (`docker events`, start events by Compose project, live during the run): per row, 9 labs × 7 containers = 63 starts, plus 1 for the run's in-node package lab. Per cell: 90 labs, 56 in `lab.Standard()` (6 containers) and 34 in `lab.Upstream()` (7), so 574 starts; TP-229's lab timeline of its full lab on 0369d34e shows the 90 matrix labs.
- Matrix wall time: per row, `TestCensorMatrix` took 915 s on 632ed83a (rows 160–865 s; reality, with the 7.5-minute rhythm hold, the longest). Per cell, the 90 labs of TP-229's full lab on 0369d34e started between 19:51:57 and 20:30:40 (at least 39 minutes); a targeted per-cell `TestCensorMatrix` run at this branch's base (80c10648) ran 23 of 90 cells before labctl's 60-minute cap, its labs waiting on the subnet lock.
- `go test` runs at most GOMAXPROCS tests at once, so on a runner with fewer cores than rows some rows wait for a slot. `transports` lists the long rows first (reality, then udp, both holding their tunnel 7.5 minutes), so they never wait: the matrix should take about its longest row, reality's (~865 s), plus a lab start.

## Review findings
- [x] R1.1 The reset's snapshot missed routes in every table and addresses: a `thinkpol up` killed after its grace could leave routes the reset and check didn't see. The snapshot now reads `ip -4/-6 route show table all` and `ip -br addr`, and the reset deletes leftover routes and addresses after the links go; neighbour entries, route expiry, the linkdown flag and RA routes are left out (the kernel changes them on its own).
- [x] R1.2 The reset's comment said `censord -reset` removes the verdict log; the file cleanup of /run/censor does. Comment fixed.
- [x] R1.3 Acceptance boxes 1 and 2 said "a full lab" and "the same commit"; reworded to what was shown.
- [x] R1.4 `transports` lists the longest rows first (reality, udp).

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
- 2026-11-16 backlog → in-progress, owner: agent-tp-240
- 2026-11-17 one lab per row (lab/results_test.go `TestCensorMatrix`, lab/matrixreset_test.go), `censord -reset` (lab/censor `ClearRouter`), docs: lab/README.md, lab/censor/doc.go; the `upstream` fields of `censorCase` and `transport` are gone, every row runs in `lab.Upstream()`
- 2026-11-17 mutation, reset skipped (`matrixRow.reset` returns `r.check()` first): `TestCensorMatrix/^plain-tcp` failed all 10 cells, e.g. "the lab's reset after the cell didn't hold: router: left after the cell: file /run/censor; router: 3 conntrack entries outlived the reset"
- 2026-11-17 mutation, `ClearRouter` doesn't flush conntrack: `TestClearRouter` failed, "3 conntrack entries after the reset, want none"; mutation, `nodeState.diff` never reports an extra: `TestNodeState` failed
- 2026-11-17 runs: `TestClearRouter` in a lab node passed; per-row `TestCensorMatrix` on 9333aa5e twice, every reset held, but 3 and then 2 rows got no lab (the subnet lock's deadline, before TP-229), those rows passed on a re-run; per-row `TestCensorMatrix` on 632ed83a (TP-229 merged) passed, 90 of 90 cells, RESULTS.md written
- 2026-11-17 verdicts: RESULTS.md from the per-row run on 632ed83a vs the per-cell one from TP-229's full lab on 0369d34e (matrix files, lab/censor and lab/censord identical to this branch's base): the 90 verdicts and the header are identical; details differ only where they vary from run to run in per-cell runs too (the prober's random probes and their answers, which counting signal flags reality's rekey first)
- 2026-11-17 not run: a full `make lab-test` (targeted runs only until this rework lands); `make lint` and `make test` green on 632ed83a; lab commit 632ed83a
- 2026-11-17 in-progress → review
- 2026-11-17 review round 1: fix R1.1–R1.4, merge
- 2026-11-17 R1.1–R1.4 done; origin/rewrite merged (TP-200, TP-238); `make lint`, `make test` green on 684a9ffe; `TestNodeState` passed; mutation, `undoAddressing` drops the address deletes: `TestNodeState` failed
- 2026-11-17 `TestCensorMatrix` on 684a9ffe failed: 921 s; 8 rows passed, every reset held (udp 681 s); reality's reset after `ip-blocklist (entry)` (fail, as expected) left 3 router conntrack entries, so the row's last 7 cells errored and RESULTS.md wasn't written. Likely cause: the killed client's orphaned TCP sockets kept retransmitting, and one retransmission crossed after the single `censord -reset`. Fix: `matrixRow.clearRouter` flushes again until `nf_conntrack_count` reads 0 (up to 30 s)
- 2026-11-17 handoff: the `clearRouter` fix is untested in a lab (this round allowed one matrix run). A `TestCensorMatrix` run is needed before the merge
