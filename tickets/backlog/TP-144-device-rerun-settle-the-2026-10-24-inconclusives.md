---
id: TP-144
title: "Device re-run: settle the 2026-10-24 inconclusives"
milestone: M2
area: tests
repo: thinkpol-vpn
size: M
needs_human: macos
depends_on: [TP-140, TP-141]
refs: [D6, N2, RR12]
owner: ""
branch: ""
---

## Goal
One owner session on the Mac, about 45 minutes, settles what the 2026-10-24 macOS device run left failed or inconclusive, with a device kit whose empty captures and silent commands can no longer pass for evidence.

## Scope
**The checklist** (each item's result goes into Notes, and into the ticket it serves):
- The stop: Ctrl-C after a sleep, a network change and a disconnect/connect in the same session, with `kill -INT <pid>` as the control. The stop counts only when the log has the `shutting down` line.
- Exit-address checks that work: `curl -4 -sS` and `curl -6 -sS`, each printing its error and exit code.
- The corrupt route record warning (TP-108): the record's content saved before each start, the runs in the right order. If TP-124 has landed by then, check its set-aside instead.
- The quick pass above the hook (TP-126, TP-095): the step the 2026-10-24 run skipped.
- `set skip on lo` and `set skip on lo0`, each with `pfctl -s Interfaces -v` and health recorded (for TP-143).
- The connect-on-boot reboot with the Wi-Fi link recorded before and after; the crash trace (TP-141) and `runs` under launchctl read after it (for TP-142); health with no link (TP-140).
- The ping to the device's own overlay IPv4: step 7 failed, and no earlier run had tried it, so investigate rather than re-run (UDP DNS to the same address worked, and `router.reflected` counted the packets). Either it answers, or the finding goes to a ticket.
- The tunnel on a second network: the hotspot leg never came up (five dials `no answer within 6s`, nothing reached the exit). Use a network that passes UDP to the exit, and keep each attempt's file.
- TP-082's harness, its first run, if TP-082 is ready by then.

**Device kit prerequisites**, fixed before the session:
- every leak capture has a positive control (a packet it must see) and waits until the capture is listening, so an empty capture isn't blind;
- a link-state record (the physical interface's status and network) with every snapshot;
- curl that shows errors (`-sS`, the exit code on its own line, quoted URLs);
- a stop verified by the `shutting down` log line, halting the run when it's missing;
- the group cleanup that actually runs, saves its output and fails loudly;
- the corrected Expect lines (the exempt table's link-scoped count under a preset with `local`, the log lines the code really writes after a wake and at start, the session's own groups rather than `id -Gn`).

**The runbook format** (owner's request):
- a navigation table with links at the top;
- one linear path, no branches to jump between;
- each step as **Do** / **What happens** / **Expect**;
- every command in a code block.

## Out of scope
- Fixing what the run finds: each finding goes to its ticket (TP-140, TP-142, TP-143, TP-124) or a new one.
- The native-IPv6 leak paths: TP-096, blocked on a network with native IPv6.
- The device kit itself stays outside the repo; this ticket records its results, not its code.

## Acceptance
- [ ] the kit prerequisites are in place and the runbook follows the format above
- [ ] each checklist item has a result in Notes (PASS, FAIL or a reason), with its evidence named by step
- [ ] the results are copied into TP-142, TP-143 and the other tickets they serve, and new findings are filed and named in the Log

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list: done before the M2 lanes start. The phase rule says macOS refactors end with a clean device run, and the 2026-10-24 run came back with two FAILs and several INCONCLUSIVEs.
- **Dependencies.** Depends on TP-140 and TP-141, which change what the run checks (health with no link, the crash trace). TP-142 and TP-143 depend on this run, not the reverse: they read its results. TP-138 and TP-124 aren't dependencies; if they land first, the run checks their behaviour too.
- **Why each item (device evidence, the 2026-10-24 macOS device run):**
  - step 14: Ctrl-C didn't stop the agent and the log has no `shutting down`; the five Ctrl-Cs in fresh sessions all worked, and before the phase the kit's `kill -INT` always did;
  - the HTTPS exit-address checks printed nothing (`-s`, no `-4`), so egress through the exit isn't shown anywhere in that run;
  - step 17 (TP-108's corrupt record) ran in the wrong order and saved no record;
  - step 21 (the quick pass) was skipped;
  - step 20's `set skip on lo` showed no skip line at all;
  - the connect-on-boot reboot had no Wi-Fi link, unnoticed, and the agent crashed once (exit 2);
  - an en0-bound capture held 0 packets while a curl over en0 succeeded, which weakens every empty-capture verdict of that run;
  - the group cleanup didn't take effect, and its output wasn't saved.
- Evidence stays private: Notes name steps and results, never local paths, hostnames or addresses.

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run and code-health review: before-M2 list)
