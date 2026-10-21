---
id: TP-126
title: "IPv6 guard: a dormant table or a foreign chain goes unrepaired"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
A foreign change that turns the IPv6 leak guard off is repaired (or reported as not enforced), as DESIGN promises for the changes the guard already watches.

## Scope
- **Linux, proven in the lab (2026-10-22).**
  - **Dormant table.** `nft add table inet thinkpol-guard '{ flags dormant; }'` turns the guard off: the kernel unregisters a dormant table's base chains, and an IPv6 ping out the physical interface leaks. Nothing repairs it: `touchesGuard` (`firewall/guard_linux.go`) ignores `NFT_MSG_NEWTABLE`, and `whole()` doesn't look at the table's flags, so `Apply` returns early, even from the one-minute backstop, and `GuardEnforced` stays true.
  - **Foreign chain.** A base chain added to the guard's own table, such as a `pre` chain at output that sets the route mark, is never seen: `touchesGuard` ignores `NFT_MSG_NEWCHAIN`, and `whole()` checks only `output`. That one leaked too.
  - **Fix.** Watch `NEWTABLE` and `NEWCHAIN`. `whole()` requires table flags of 0 and exactly one chain, `output`. `Apply`'s rebuild already replaces the table.
- **Nit.** A policy change on `output` is caught only by the backstop, not by the watch. It fails closed. Watching `NEWCHAIN` fixes it too.
- **macOS, suspected from reading the code only. Check on paper and, if confirmed, add tests with the fake pfctl.**
  - `set skip on <physical interface>` disables pf filtering on that interface, and it doesn't show in `pfctl -s rules`. Nothing checks `pfctl -s Interfaces`.
  - `hooked()` scans only the main ruleset, so a `pass quick` in another `com.apple/*` anchor evaluated before the guard's anchor isn't seen.
- Fix the residual-risks row on foreign changes (TP-077's table: "repaired within about 1 s"), so it says what is and isn't repaired.

## Acceptance
- [ ] lab tests: a dormant guard table, and a foreign base chain in the guard's table, are each repaired, and the leak test then blocks. Mutation: dropping either new check fails its test
- [ ] macOS: each suspicion is confirmed with a fake-pfctl test and fixed, or shown not to apply, with the reason in the Log
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-077's correctness review (2026-10-22) while checking the residual-risks table against the code, then proven by a throwaway lab test (`TestGuardDormantGap`, not committed). The lab table:
  - dormant: no signal, still dormant after a re-apply, leaks;
  - policy drop: no signal, repaired by the backstop, no leak;
  - an extra accepting base chain: no signal, stays, no leak;
  - add then delete a chain: signal, clean;
  - a mark-setting base chain in the guard's table: signal, stays, leaks.

## Log
- 2026-10-22 created in backlog (lab-confirmed gap from TP-077's review)
