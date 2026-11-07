---
id: TP-144
title: "Device re-run: the boot trace and the pf skip listing"
milestone: M2
area: tests
stream: verification
repo: thinkpol-vpn
size: S
needs_human: macos
depends_on: [TP-140, TP-141]
refs: [D6, N2, RR12]
owner: ""
branch: ""
---

## Goal
One short owner session on the Mac produces the evidence TP-142 and TP-143 need: the boot trace of a connect-on-boot reboot and pfctl's listing of a skipped interface.

## Scope
**The checklist** (each item's result goes into Notes, and into the ticket it serves):
- `set skip on lo` and `set skip on lo0`, each with `pfctl -s Interfaces -v` and health recorded (for TP-143).
- The connect-on-boot reboot with the Wi-Fi link recorded before and after; the crash trace (TP-141) and `runs` under launchctl read after it (for TP-142).

**Device kit prerequisites**, fixed before the session:
- a link-state record (the physical interface's status and network) with every snapshot;
- the corrected Expect lines (the exempt table's link-scoped count under a preset with `local`, the log lines the code really writes after a wake and at start, the session's own groups rather than `id -Gn`).

**The runbook format** (owner's request):
- a navigation table with links at the top;
- one linear path, no branches to jump between;
- each step as **Do** / **What happens** / **Expect**;
- every command in a code block.

## Out of scope
- Fixing what the run finds: each finding goes to its ticket (TP-142, TP-143) or a new one.
- The other 2026-10-24 inconclusives and their kit prerequisites: TP-180 (after the MVP).
- The native-IPv6 leak paths: TP-096, blocked on a network with native IPv6.
- The device kit itself stays outside the repo; this ticket records its results, not its code.

## Acceptance
- [ ] the kit prerequisites are in place and the runbook follows the format above
- [ ] each checklist item has a result in Notes (PASS, FAIL or a reason), with its evidence named by step
- [ ] the results are copied into TP-142 and TP-143, and new findings are filed and named in the Log

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 2): done before the M2 lanes start. The phase rule says macOS refactors end with a clean device run, and the 2026-10-24 run came back with two FAILs and several INCONCLUSIVEs.
- **Dependencies.** Depends on TP-140 and TP-141, which change what the run checks (health with no link, the crash trace). TP-142 and TP-143 depend on this run, not the reverse: they read its results.
- **Why each item (device evidence, the 2026-10-24 macOS device run):**
  - step 20's `set skip on lo` showed no skip line at all;
  - the connect-on-boot reboot had no Wi-Fi link, unnoticed, and the agent crashed once (exit 2).
- Evidence stays private: Notes name steps and results, never local paths, hostnames or addresses.
- Split 2026-11-07 (owner's MVP cut): the other 2026-10-24 inconclusives (the stop, exit-address checks, the corrupt route record, the quick pass, health with no link, the overlay ping, the second network, TP-082's first run) and their kit prerequisites moved to TP-180.

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run and code-health review: before-M2 list)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 2)
- 2026-11-07 split (owner's MVP cut): only TP-142's boot trace and TP-143's pfctl listing stay; the rest → TP-180
