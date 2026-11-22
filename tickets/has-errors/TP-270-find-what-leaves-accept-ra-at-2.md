---
id: TP-270
title: "Find what leaves accept_ra at 2 after the supervisor's tests"
milestone: M2
area: dataplane/agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-270"
branch: "tp-270-accept-ra-left-at-2"
---

## Goal
After `internal/agent/supervisor`'s tests, a lab node has `net.ipv6.conf.{default,eth0,lo}.accept_ra` at 2 (clean: 1), seen by the node pool's reset (TP-269). Close restores it (`egress_linux_test.go` asserts that), so some test or crash-recovery path leaves it. If the product can leave it on a real host after the VPN stops, a server keeps taking router advertisements. Find the path, and fix the product if it is there (else the test).

## Scope
- Name the test, and the code path in it, that leaves `accept_ra` at 2 (bisect the package's tests in a lab node, reading the sysctls after each).
- If the path is the product's (a stop, a crash recovery, a forwarding put back without its `accept_ra`), fix it there; if it is only the test's, fix the test.

## Acceptance
- [x] The cause named, with evidence (the test and the code path, the sysctls before and after). `TestClearLeftoversLeavesWhatItCantProveDead/an_unreadable_record`, through `leftByADeadSupervisor`: test-only (Notes). Lab bisect on rewrite 6832b93c: the whole package, and that subtest alone (`RUN=`), each leave `net.ipv6.conf.{default,eth0,lo}.accept_ra` 2 (clean: 1) in the reset's log; the package without it (`SKIP=`) leaves none.
- [x] The fix. The fixture's cleanup puts the dead supervisor's record back and runs `ClearLeftovers`, the product's own undo (leftovers_linux_test.go ~58). On the way, a product hole fixed: `enable` returned on a refused `accept_ra` write or a `sideKeys` error without putting back the `accept_ra` values it had written (forwarding.go ~230, `fail`). Lab on 6de23b4f: the package passes and the reset undid nothing.
- [x] A test that fails when `accept_ra` is left changed after the path that left it. The fixture's cleanup checks every `net.ipv6.conf.*.accept_ra` against its value before the dead supervisor ran (leftovers_linux_test.go ~66), so every test using it fails on a leftover; `TestForwardingThatFailsToTurnOnLeavesAcceptRAAsItWas` (forwarding_test.go ~285) covers the failed start. Mutations in the Log.

## Notes
- Cause: `leftByADeadSupervisor` serves egress with uplink `lo` and IPv6, so `enable` sets `accept_ra` 2 on every interface at 1 (default, eth0, lo, the test's tplo-ra0) before IPv6 forwarding. In "an unreadable record" the record is corrupted, so `ClearLeftovers` rightly touches nothing: forwarding stays on, with `accept_ra` 2 as it must be while forwarding is on. Then the test's cleanups (`forwardingOff`, `setSysctl`) turn both forwarding switches off with plain writes, which don't put `accept_ra` back.
- Why the product can't reach it: the supervisor leaves `accept_ra` 2 only while the family's forwarding it turned on stays on (a switch it can't turn off keeps the whole family recorded, `restoreFamily`; an unreadable record leaves everything). Forwarding going off underneath without `accept_ra` is the test's plain write, not a supervisor path. Close, a successor's adoption and `ClearLeftovers` all put `accept_ra` back with the switch (TestForwardingTurnedOnForwardsOnlyTheSpaces, TestClearLeftoversUndoesADeadSupervisors).
- Product hole found on the way, fixed here: a failed IPv6 start (an `accept_ra` write refused, or `sideKeys` failing) left the values already written at 2, with forwarding off and no record. Now every failure before the switch is flipped puts them back (doc.go, "Root forwarding", says so).
- `default` is written to 2 on purpose, so an interface that appears while IPv6 forwarding is on (a re-plugged uplink) keeps taking advertisements; it is recorded and put back like the rest.

## Review findings
Round 1 (2026-11-22).
- [ ] R1.1 `enable`'s `fail` (forwarding.go ~230) sets `f.fams[fam] = c` and calls `restoreFamily`, which also writes the switch back to `was` when it reads the "1" written. If another program (a container runtime, say) turns that family's forwarding on between our read and the failure, we'd switch its forwarding off; and if that write fails, `restoreFamily` returns early with `f.fams[fam]` still set, so `ensure` saves a record and we'd own and confine someone else's forwarding. Before the switch is flipped nothing of ours is there to restore. Fix: the undo puts back only the `c.Before` entries that still read their Written value (the same `held` rule), joins their errors, and never touches `f.fams` or the switch. Name it for what it does (`undo`, not `fail`).
- [ ] R1.2 forwarding_test.go: the `sideKeys` failure path has no case (`fakeKernelSys`'s Glob can't fail): add a hook and a third case, mutation-checked (drop the undo on that path → the test fails). Add a case for R1.1's race: the switch reads "1" (someone else's) when the attempt fails → it stays "1", not owned, no record.
- [ ] R1.3 doc.go ~210: "so a failed start leaves none changed" overclaims when a put-back write fails: say it puts back the accept_ra values it wrote (what it can't is in the error).
- [ ] R1.4 Test failure messages in got/want form: forwarding_test.go ("IPv6 forwarding = %s after the failed attempt, want 0"), leftovers_linux_test.go ~67 ("%s = %s after the dead supervisor's leftovers were cleared, want %s").
- [ ] R1.5 The Notes say the product can't leave accept_ra at 2. Not quite: `load()` (forwarding.go ~142-149) drops a family whose switch no longer holds what was written, together with its Before entries, so if the supervisor crashes and an admin or networkd turns that forwarding off, accept_ra stays 2 for the rest of the boot (low harm: 2 acts like 1 while forwarding is off). Correct the Notes; the fix goes into a follow-up ticket, not this branch.

## Log
- 2026-11-20 created in backlog (TP-269 review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-270
- 2026-11-22 lab bisect on rewrite 6832b93c (`make lab-gotest PKG=./internal/agent/supervisor/...`, -v): whole package (100 s) and `RUN=TestClearLeftoversLeavesWhatItCantProveDead/an_unreadable_record` (231 s, incl. queue) each leave default/eth0/lo accept_ra 2 in the reset's log; `SKIP=` the same subtest (155 s): the reset undid nothing. Cause test-only (Notes)
- 2026-11-22 fix: the dead-supervisor fixture's cleanup puts its record back, runs ClearLeftovers and checks every accept_ra against its value before (leftovers_linux_test.go); enable's failure paths before the switch put back the accept_ra values written (forwarding.go `fail`), doc.go updated; new unit test TestForwardingThatFailsToTurnOnLeavesAcceptRAAsItWas
- 2026-11-22 mutations (each failed, then restored; lab ones in a scratch worktree, never pushed): `fail` replaced by a plain return on the refused accept_ra write → "an accept_ra write refused" fails (default accept_ra 2); the switch's failure returned without `fail` → "the switch refused" fails (default and eth0 2); restoreFamily skipping `default/` keys (lab, RUN=TestClearLeftovers) → TestClearLeftoversUndoesADeadSupervisors fails at the fixture's check (default 2, was 1), which no earlier test caught; the cleanup writing the record elsewhere (lab) → "an unreadable record" fails (ClearLeftovers can't read the record; lo, tplo-ra0, default, eth0 at 2)
- 2026-11-22 lab on 6de23b4f (rewrite merged in, TP-275's image pin included): `make lab-gotest PKG=./internal/agent/supervisor/...` passes, the reset undid nothing (237 s). No full `make lab-test`: the orchestrator runs full labs on rewrite after merges
- 2026-11-22 out of scope: `enable` writes accept_ra and the switch before `ensure` saves the record, so a crash between the writes and the save leaves them unrecorded (forwarding on, unconfined, accept_ra 2) for a successor to take as the node's own
- 2026-11-22 make lint and make test green on 6de23b4f
- 2026-11-22 in-progress → review
- 2026-11-22 review → has-errors (round 1: R1.1–R1.5)
