---
id: TP-276
title: "Forwarding's record is saved after its sysctl writes"
milestone: M2
area: agent/supervisor
stream: core
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-276"
branch: "tp-276-forwarding-record-before-writes"
---

## Goal
`enable` (internal/agent/supervisor/forwarding.go) writes accept_ra and the forwarding switch (~240, ~257) and `ensure` saves the record only after (~217). A crash (SIGKILL, OOM) in that window, or a failed save after a successful `enable` (`applyTables` only logs a warning), leaves forwarding on with no record. The next supervisor loads nothing, `installIsolation` rebuilds with `owned` false (isolation_linux.go ~323), and `enable` won't own a switch already at 1 (~224): a restarted exit node forwards that family for everyone, unconfined by its isolation tables, for the rest of the boot, with accept_ra 2. When this is done, every sysctl the supervisor writes is recorded before it is written, or put back, whatever the point of failure.

## Scope
- Save the record (Main.Written "1", Before) before flipping the switch, so a successor whose switch never flipped still puts accept_ra back; then save Side after.
- Treat a failed save as a failed apply, not a warning.
- `load` drops a family whose switch no longer holds what was written together with its Before entries (forwarding.go ~142-149): if the supervisor crashes and an admin or networkd turns that forwarding off, accept_ra stays 2 for the rest of the boot (low harm: 2 acts like 1 while forwarding is off). Have `load` put back the Before entries of a family it doesn't adopt when they still read their Written value.
- Update the "Root forwarding" section of the package doc (doc.go) and drop its "Not yet" line.

## Out of scope
- Forwarding someone else turned on (a container runtime): left alone, as now.

## Acceptance
- [x] Tests that kill or fail at each point (after the accept_ra writes, after the switch, a failed save) and show the successor puts everything back or owns it (confined by its tables).
- [x] A test for `load` with a family's switch turned off underneath: its accept_ra put back.
- [x] Every new test mutation-checked, mutations in the Log.
- [x] `make lab-gotest PKG=./internal/agent/supervisor/...` green, the reset undoing nothing.

## Notes
- Found in TP-270's review (R1.5) and its implementer's out-of-scope note.
- New order in `enable` (forwarding.go ~249): IPv6's accept_ra values at 1 are planned into Before and the record saved (~286) before any is written; then Side's earlier values are read and Main.Written set to "1" and saved (~308) before the switch is written; what Side holds after is saved by `ensure`'s save. A Main.Written still empty marks a switch never written: never adopted. A failed save fails the attempt (`undo`: Before entries still at 2 put back, the family given up, the switch untouched), so `enable` succeeds only with the switch already recorded; a failed save after it (ensure's) leaves the pre-switch record, which covers it. `load` (~138) puts back a non-adopted family's Before entries that still hold 2, and fills Side entries a crash left without Written with what they hold then (best evidence; a change someone made to one of them between the crash and the successor is taken as the supervisor's).
- "Failed save as a failed apply": the failed save fails the family's enable and puts everything back, returned by `ensure`. `applyTables` still logs forwarding errors as a warning (egress off for that family) rather than failing SetSpaces: nothing is left unrecorded, and failing there after the tables' flush would leave the tables enforcing a state `restoreEgress` then says they don't.
- The file: temp file + rename, no fsync (as before): tmpfs keeps it across a process crash, a reboot clears it with the sysctls. A previous boot's record is ruled out by DefaultRuntimeDir being /run (tmpfs); only tests set RuntimeDir. A successor can't start while its predecessor lives: the record is read and written only under the node's supervisor role (netcfg's non-blocking flock, taken by NewRoot before `load`; ClearLeftovers holds the same).
- Accepted: a switch someone else turns on between `enable`'s read of 0 and its write of 1 is taken as the supervisor's, by the live process (as before) and now by a successor after a crash in that window (doc.go says so).

## Review findings
- [ ] R1.1 doc.go "Root forwarding" (and the Notes): the accepted race's window is wrong for a successor. It runs from the pre-switch save until the successor's load, unbounded while the service stays down (start limit hit, admin stopped it): killed between the save and the switch write, a container runtime sets ip_forward=1, hours later thinkpol starts, adopts it, its tables drop the runtime's forwarded traffic, and Close or uninstall turns it off. Adopting stays (fails closed); reword the window. Update a RESIDUAL-RISKS.md row on forwarding adoption if one exists, else say in the ticket why none is needed.
- [ ] R1.2 forwarding.go `enable`: the `return undo(err)` on Glob("net/ipv6/conf/*") failing has no test; with the family set early, `return err` there would leave IPv6 recorded with Main.Written empty. A row refusing that pattern in TestForwardingThatFailsToTurnOnLeavesAcceptRAAsItWas; mutation `return err` must fail it.
- [ ] R1.3 The "never marked" marker (Main.Written empty until the pre-switch save) has no test: a case where IPv6 forwarding is set to 1 by someone else right after the accept_ra save, snapshot, and the successor neither adopts it nor turns it off (and puts accept_ra back). Mutation: c constructed with Written "1" must fail it.
- [ ] R1.4 An accept_ra put-back write that fails (in `undo`, or in `load` for a family it doesn't adopt) drops the family and the next save deletes the record: accept_ra stays 2 unrecorded (and ClearLeftovers says the tables stay with the record gone). Keep the entries whose put-back failed in the record (not adoptable: Main.Written empty), so a later load retries them. Test and mutation.
- [ ] R1.5 Style: no discarded errors (`c.Side[i].Written, _ = f.sys.Read(...)` in `enable` and `load`); the fill-then-DeleteFunc step written twice becomes one method used by both; crashSys.snapshot calls t.Helper(); crashSys's methods together (afterWriteSys after them); errors.Is(err, fs.ErrNotExist) instead of os.IsNotExist.
- [ ] R1.6 docs/design/api-overview.md: forwarding.json is written "only when it turned forwarding on" → "while it turns, or has turned, forwarding on".

## Log
- 2026-11-22 created in backlog (TP-270 review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-276
- 2026-11-22 fix: every forwarding sysctl recorded before it is written (forwarding.go `enable`: accept_ra planned and saved first, the switch with Side's earlier values saved before it is flipped; a failed save undoes the attempt); `load` puts back a non-adopted family's accept_ra still at 2 and fills unrecorded Side values; doc.go "Root forwarding" updated, its "Not yet" line dropped; ClearLeftovers' load error says "read or acted on". New tests TestForwardingKilledAtAnyWriteIsPutBackOrAdopted (a copy of the sysctls and record before and after each of the 4 writes, a fresh supervisor loading each), TestForwardingRecordThatCannotBeSavedFailsTheAttempt (save failing before the accept_ra writes, before the switch, after the switch), TestForwardingRecordOfASwitchTurnedOffPutsBackAcceptRA
- 2026-11-22 mutations (each failed, then restored): the save before the switch dropped → killed after either switch, failed save before/after the switch fail; the save before the accept_ra writes dropped → killed after default's/before and after eth0's accept_ra write fail; load not filling unrecorded Side values → killed after either switch and failed save after the switch fail (eth1 IPv6 forwarding 0, was 1); load not putting back a non-adopted family's accept_ra → the accept_ra crash points and TestForwardingRecordOfASwitchTurnedOffPutsBackAcceptRA fail; the pre-switch save's error ignored → failed save "before the switch" fails; load putting back accept_ra without `held` → TestForwardingRecordOfASwitchTurnedOffPutsBackAcceptRA fails (eth0 1, want 0)
- 2026-11-22 make lint and make test green on 2035ee57; lab on 2035ee57: `make lab-gotest PKG=./internal/agent/supervisor/... COUNT=1` passes (52.7 s), the new tests ran as root there, the reset undid no sysctl (worker sandbox roots, supervisor lock files and /run/netns only, as on rewrite). No full `make lab-test`: the orchestrator runs full labs on rewrite after merges
- 2026-11-22 not verified: a real SIGKILL of a supervisor in the lab (the crash points are unit tests on the fake kernel); confinement of an adopted family is shown by `owned` (which builds the forward chain's drop) and the existing lab test TestForwardingCloseCannotTurnOffStaysConfined, not by a new lab test
- 2026-11-22 in-progress → review
- 2026-11-22 review → has-errors: R1.1–R1.6 (four reviewers, two model families: change sound, the applyTables choice accepted)
- 2026-11-22 has-errors → in-progress, owner: agent-tp-276
