---
id: TP-132
title: "service uninstall: clean up after a crashed server, and never get stuck"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-046]
refs: [docs/design/security.md#node-safety]
owner: "agent-tp-132"
branch: "tp-132-uninstall-after-a-server-crash"
---

## Goal
`thinkpol service uninstall` leaves a host clean after a crashed server too, and a cleanup error never leaves uninstall stuck with the service disabled and its files still on disk.

## Scope
- **Server leftovers.**
  - **Today:** uninstall runs only a device's cleanup (`agent.Platform.ClearHost`: routes, guard, DNS). A server SIGKILLed, or killed after its stop timeout, leaves things only its supervisor's next start would undo (supervisor/doc.go, start-time cleanup):
    - the forwarding sysctls it turned on (and `accept_ra`);
    - its isolation nftables tables;
    - root-namespace routes and veths.
  - **Problem:** uninstall has just removed the binary, so there is no next start.
  - **Fix:** run the supervisor's start-time cleanup from uninstall too, under the host lock. Report what was undone; report what is left only if it can't be undone.
- **No stuck uninstall.**
  - **Today:** uninstall stops and disables the service first, then fails hard on any `ClearHost` error. An agent's own start treats the same errors as warnings.
  - **Fix:** report the error, say what was left, and offer `-force` to remove the definition and binary anyway. Name the concrete failure that motivated it, e.g. a DNS backup record `readBackup` rejects.

## Acceptance
- [x] lab: a connected server SIGKILLed, then uninstalled at once (with the restart held off, as TP-046's test does), leaves no supervisor table, forwarding sysctl it set, veth or route
- [x] a unit test: a ClearHost error makes uninstall report and stop; `-force` completes it
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-046's round-2 reviews (2026-10-23).

## Review findings
- [ ] R1.1 docs: api-overview-reference.md service uninstall section (synopsis, -force, sample output with the "undid what a crashed agent left" lines, the stop-on-failure error); api-overview.md install.go line range
- [ ] R1.2 tests check IPv6 forwarding (and accept_ra the test set from 1) after the clear, in lab/service_server_test.go and leftovers_linux_test.go
- [ ] R1.3 subtest: forwarding still on (ip_forward=0 refused) keeps the isolation tables and ClearLeftovers errors
- [ ] R1.4 a failed ClearHost with nothing left on disk is a warning and uninstall exits 0 (onDisk returns ""); unit test
- [ ] R1.5 delete only the tables isolationTables() lists, report its listing error; unit test for nothing listed → nothing touched
- [ ] R1.6 nits: install.go comment wrap; name the families still forwarding; ClearHost doc matches the veth-error path; service doc.go lists the per-space cgroup dirs left after a crash

## Log
- 2026-10-23 created in backlog (TP-046 review round 2)
- 2026-11-07 backlog → in-progress, owner: agent-tp-132
- 2026-11-07 finisher: branch has the fix (9e6a61c: ClearHost also runs supervisor.ClearLeftovers under the supervisor role and reports what it undid; uninstall stops on a failed clear, saying what is left on disk, and -force completes it) and tests (64eb4f3: lab TestServiceUninstallAfterAServerCrash; TestUninstallStopsOnAFailedClearAndForceCompletesIt, systemd and launchd; TestClearLeftovers*)
- 2026-11-07 finisher: merged rewrite 7852af8 (head c66ccc8) in as cc7d3d1; make lint green, make test green (TestUninstallStopsOnAFailedClearAndForceCompletesIt passes)
- 2026-11-07 finisher: full make lab-test passed on cc7d3d1 (LAB_P=4, run alone): lab/ packages ok (TestServiceUninstallAfterAServerCrash included, no skip path), gotest ok for 36 packages
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.1–R1.6)
