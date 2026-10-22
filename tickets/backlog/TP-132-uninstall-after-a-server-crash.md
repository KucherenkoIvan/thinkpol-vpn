---
id: TP-132
title: "service uninstall: clean up after a crashed server, and never get stuck"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-046]
refs: [docs/design/security.md#node-safety]
owner: ""
branch: ""
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
- [ ] lab: a connected server SIGKILLed, then uninstalled at once (with the restart held off, as TP-046's test does), leaves no supervisor table, forwarding sysctl it set, veth or route
- [ ] a unit test: a ClearHost error makes uninstall report and stop; `-force` completes it
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-046's round-2 reviews (2026-10-23).

## Log
- 2026-10-23 created in backlog (TP-046 review round 2)
