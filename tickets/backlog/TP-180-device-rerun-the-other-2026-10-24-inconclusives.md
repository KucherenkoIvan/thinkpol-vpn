---
id: TP-180
title: "Device re-run: the other 2026-10-24 inconclusives"
milestone: later
area: tests
repo: thinkpol-vpn
size: M
needs_human: macos
depends_on: [TP-144]
split_from: TP-144
refs: [D6, N2, RR12]
owner: ""
branch: ""
---

## Goal
An owner session on the Mac settles what the 2026-10-24 macOS device run left failed or inconclusive beyond TP-144's two items, with a device kit whose empty captures and silent commands can no longer pass for evidence.

## Scope
**The checklist** (each item's result goes into Notes, and into the ticket it serves):
- The stop: Ctrl-C after a sleep, a network change and a disconnect/connect in the same session, with `kill -INT <pid>` as the control. The stop counts only when the log has the `shutting down` line.
- Exit-address checks that work: `curl -4 -sS` and `curl -6 -sS`, each printing its error and exit code.
- The corrupt route record warning (TP-108): the record's content saved before each start, the runs in the right order. If TP-124 has landed by then, check its set-aside instead.
- The quick pass above the hook (TP-126, TP-095): the step the 2026-10-24 run skipped.
- Health with no link (TP-140).
- The ping to the device's own overlay IPv4: step 7 failed, and no earlier run had tried it, so investigate rather than re-run (UDP DNS to the same address worked, and `router.reflected` counted the packets). Either it answers, or the finding goes to a ticket.
- The tunnel on a second network: the hotspot leg never came up (five dials `no answer within 6s`, nothing reached the exit). Use a network that passes UDP to the exit, and keep each attempt's file.
- TP-082's harness, its first run, if TP-082 is ready by then.

**Device kit prerequisites**, fixed before the session:
- every leak capture has a positive control (a packet it must see) and waits until the capture is listening, so an empty capture isn't blind;
- curl that shows errors (`-sS`, the exit code on its own line, quoted URLs);
- a stop verified by the `shutting down` log line, halting the run when it's missing;
- the group cleanup that actually runs, saves its output and fails loudly.

The runbook follows TP-144's format.

## Out of scope
- Fixing what the run finds: each finding goes to its ticket (TP-140, TP-124) or a new one.
- TP-142's boot trace and TP-143's pfctl listing: TP-144.

## Acceptance
- [ ] the kit prerequisites are in place and the runbook follows TP-144's format
- [ ] each checklist item has a result in Notes (PASS, FAIL or a reason), with its evidence named by step
- [ ] the results are copied into the tickets they serve, and new findings are filed and named in the Log

## Notes
- Split from TP-144, 2026-11-07, owner's MVP cut.
- **Why each item (device evidence, the 2026-10-24 macOS device run):**
  - step 14: Ctrl-C didn't stop the agent and the log has no `shutting down`; the five Ctrl-Cs in fresh sessions all worked, and before the phase the kit's `kill -INT` always did;
  - the HTTPS exit-address checks printed nothing (`-s`, no `-4`), so egress through the exit isn't shown anywhere in that run;
  - step 17 (TP-108's corrupt record) ran in the wrong order and saved no record;
  - step 21 (the quick pass) was skipped;
  - an en0-bound capture held 0 packets while a curl over en0 succeeded, which weakens every empty-capture verdict of that run;
  - the group cleanup didn't take effect, and its output wasn't saved.
- TP-138 and TP-124 aren't dependencies; if they land first, the run checks their behaviour too.
- Evidence stays private: Notes name steps and results, never local paths, hostnames or addresses.

## Log
- 2026-11-07 created in backlog (split from TP-144)
