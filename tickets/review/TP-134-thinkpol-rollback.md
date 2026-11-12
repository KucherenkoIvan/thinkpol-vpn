---
id: TP-134
title: "`thinkpol rollback`: undo what a dead agent left, as a product command"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/security.md#kill-switch]
needs_human: macos
owner: "agent-tp-134"
branch: "tp-134-thinkpol-rollback"
---

## Goal
A user (or the device-test harness) whose agent crashed can put the host back with one root command: no routes, guard, pf reference or resolver configuration of thinkpol's left.

## Scope
- `sudo thinkpol rollback`: under the host lock (refused while an agent runs), run the agent's start-time cleanup (`agent.Platform.ClearHost`, the same `up -connect=false` runs), report what it undid and what is left. With the persisted connect state (TP-046) and the kill switch (TP-048), say what rollback means for a device that should stay fail-closed after a crash: rollback is the user choosing to go back to no tunnel.
- The same command serves the harness's last-resort restore (TP-082) and the docs' crash recovery, replacing the by-hand route deletions in the runbooks.
- TP-132 (uninstall after a server crash) may share it: say which owns the supervisor's cleanup.

## Acceptance
- [x] lab: SIGKILL a connected device's agent, `thinkpol rollback` leaves the host as before `up` (routes, nft table, resolver configuration)
  - `lab/rollback_test.go` `TestRollbackAfterACrash` (service device, "everything" preset, connected, SIGKILL with the restart held off): resolv.conf, rules and routes of both families, `nft list ruleset` and links equal to before `service install`; traffic direct; the restarted agent comes up disconnected with no kill switch. Passed alone on f82eb3c+fix and in the full lab on 7721f0c
- [x] refused while an agent runs (a test)
  - unit `TestRollbackIsRefusedWhileAnAgentRuns` (nothing cleared, kill switch and record kept, nothing printed); lab: the refusal step in `TestRollbackAfterACrash` (exit 1, empty stdout, host unchanged) and `TestASecondAgentChangesNothing` runs `thinkpol rollback` beside a connected agent (exit 1, no route/rule/link/resolv.conf change)
- [x] `make lint`, `make test`, `make lab-test` pass
  - on 7721f0c (merge of origin/rewrite 5742584): lint and test green; full `make lab-test` (LAB_P=1) exit 0, lab/ ok, gotest ok for 39 packages
- [ ] macOS: device checklist step (pf anchor, reference and token record gone, routes and DNS back)
  - checklist in Notes ("Device checklist (macOS, for the owner)"); waits on the owner's device run

## Notes
- Owner's answer to the device-harness questions (2026-10-23, TP-082 question 4).
- **What rollback is** (implementer, 2026-11-12). `agent.Rollback`: under the host lock (refused with nothing touched while an agent holds it: `ErrAnotherAgent`, saying how to take a running agent's tunnel down), the parts `Platform.ClearHost` clears, now one `HostPart` each (a server's leftovers, the route table with its leak guard, the overlay, the resolver configuration, the kill switch with its place named per OS), every part tried whatever failed; then this boot's connect choice recorded down. The record is "the crash posture TP-048 leaves": without it the service's next start in the boot follows the record (meant up) and puts the kill switch back. With it the start comes up disconnected; only the toggle, on, puts the kill switch back, in the down shape (said in the report). The report says per part `none left`, `undid: …` (a server's, as uninstall) or `LEFT: …`, and exits 1 when anything is left. The service is neither stopped nor removed; a hanging start holds the lock and is stopped first (security.md). `service uninstall` keeps its output (`ClearHost` flattens the parts).
- **Who owns the supervisor's cleanup: TP-132** (decided here with TP-132's Notes). TP-132 built it (`supervisor.ClearLeftovers`, run as `ClearHost`'s server part, merged); rollback reuses it through the same `ClearHost` parts and adds nothing of its own for a server. A change to what a server's cleanup undoes goes to `ClearLeftovers`, which both commands share.
- The harness's last-resort restore (TP-082) and the private device kits' by-hand route deletions can call `sudo thinkpol rollback` now; changing them is TP-082's (not this branch's).

### Device checklist (macOS, for the owner)

Run on the Mac with thinkpol installed as the service, in a space with an entry. It never touches pf beyond thinkpol's anchor and reference. Record each step's output in the run's evidence.

| # | Do | Expect |
|---|---|---|
| 0 | `thinkpol disconnect`; `thinkpol kill-switch off`; `netstat -rn > /tmp/rb-routes-before.txt`; `scutil --dns > /tmp/rb-dns-before.txt`; `sudo pfctl -s References > /tmp/rb-refs-before.txt` | the baseline, with nothing of thinkpol's connected |
| 1 | `thinkpol rules preset everything`; `thinkpol connect`; `sudo pfctl -a com.apple/001.thinkpol-killswitch -s rules \| head -3`; `sudo ls -l /private/var/db/thinkpol/pf-killswitch.token` | connected; the anchor lists rules (the crash posture with the toggle off); the token record exists |
| 2 | `sudo launchctl kill SIGKILL system/org.thinkpol.agent; sudo thinkpol rollback` (one line: rollback must win the race with launchd's restart; if it says another agent runs, the restart won: wait for `thinkpol status` to say connected and repeat this step) | one `none left: …` line per part, the kill switch's naming `the pf anchor com.apple/001.thinkpol-killswitch, its pf reference and record`, then `recorded: disconnected, …` and `the host has no tunnel: traffic goes direct`; exit 0 |
| 3 | `sudo pfctl -a com.apple/001.thinkpol-killswitch -s rules`; `sudo pfctl -a com.apple/000.thinkpol -s rules`; `sudo pfctl -s References \| diff /tmp/rb-refs-before.txt -`; `sudo ls /private/var/db/thinkpol/` | both anchors list nothing; References as the baseline (no thinkpol reference); no `pf-killswitch.token` or `pf-guard.token` |
| 4 | `netstat -rn \| diff /tmp/rb-routes-before.txt -`; `scutil --dns \| diff /tmp/rb-dns-before.txt -`; `curl -m 5 -sI https://example.net \| head -1` | no route of thinkpol's (no utun route, no split default halves; other differences are the OS's own, e.g. ARP entries: record them); DNS as the baseline; curl answers directly |
| 5 | `thinkpol status` (repeat until the service restarted the agent); `sudo pfctl -a com.apple/001.thinkpol-killswitch -s rules` | `state: disconnected`; the anchor still lists nothing: rollback's recorded disconnect kept the crash posture from coming back |
| 6 | `thinkpol connect` (and `thinkpol rules preset` back to what you use) | connected again |

## Log
- 2026-10-23 created in backlog (TP-082 design answers)
- 2026-11-12 backlog → in-progress, owner: agent-tp-134
- 2026-11-12 built: `agent.Rollback` (internal/agent/rollback.go) and `thinkpol rollback` (cmd/thinkpol/rollback.go); `Platform.clearHost` returns one `HostPart` per part (platform.go), `ClearHost` flattens it for uninstall (output unchanged); the kill switch's place named per OS (supported_*.go); docs: security.md's way out, agent doc.go, `KillSwitchStopNote`, api-overview-reference.md (`rollback` section), api-overview.md (on-disk table), runbook-pre-controller.md; TP-132 Notes: it owns the supervisor's cleanup
- 2026-11-12 tests: unit TestRollbackIsRefusedWhileAnAgentRuns, TestRollbackClearsWhatADeadAgentLeftAndRecordsDown, TestRollbackTriesEveryPartWhateverFails, cmd TestRollbackNeedsRootAndNoArguments; lab TestRollbackAfterACrash, rollback added to TestASecondAgentChangesNothing. Mutations, each caught then restored: clear before the lock (refused test), no record saved (clear and every-part tests; lab: the restarted agent came back connected), kill switch part dropped (unit; lab: host differs from before), DNS part dropped, a failed part not an error, an empty report printing its record line (refused test; the first lab run found that bug)
- 2026-11-12 merged origin/rewrite 5742584 as 7721f0c; make lint, make test green; full make lab-test on 7721f0c exit 0 (LAB_P=1, GOFLAGS=-p=2)
- 2026-11-12 not verified: macOS (pf anchor, reference and record removal, routes, scutil DNS) has no lab: the device checklist in Notes is the owner's; box 4 stays open. Out of scope, seen: api-overview.md's `connect` row still says "only with connect-on-boot set"; the CLI reference's command list lacks kill-switch, allow-lan and connect-on-boot; TP-082's harness restore can call rollback now (TP-082's change)
- 2026-11-12 in-progress → review
