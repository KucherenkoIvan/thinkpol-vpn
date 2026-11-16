---
id: TP-224
title: "A command's status line shows the kill switch after its change"
milestone: M2
area: cmd/thinkpol
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-224"
branch: "tp-224-status-line-after-change"
---

## Goal
`thinkpol rules preset …` and `thinkpol disconnect` print a status line whose kill-switch part shows the state from before the command's own change (seen on Linux in a dry run of the M2 device checklist: the preset command printed the pre-apply kill-switch line, and disconnect printed the crash-posture suffix). A user reading it is told the wrong thing about the switch.

## Scope
- Both commands print the kill switch as it is after their change.
- Any other command with the same pattern, found by reading cmd/thinkpol.

## Out of scope

## Acceptance
- [x] Both commands print the kill switch's post-change state; tests on Linux and on macOS that fail on the old output, with the in-memory kill switch on both (no real host tools; the fix is in OS-independent node code, see Notes).
- [x] Any other command with the same pattern fixed or listed in Notes with why not.
- [ ] Mutation-checked; `make lint`, `make test`, `make lab-test` pass.

## Notes
- This changes what macOS prints, so it lands before the M2 device session.
- Cause: the CLI prints the status the node's reply carries, and the node replied before its kill switch followed the change. `rules preset` replied from the runner's `takeRules` (and, for a device waiting for a section, from `awaitSection`) and `connect`/`disconnect` from `runner.request`; the kill switch followed only at the loop's next turn, so the reply's status had the switch from before. Now each enforces the kill switch, then replies (internal/agent/dataplane.go `request` and `takeRules`, internal/agent/node.go `awaitSection`). The CLI code (cmd/thinkpol `printOutcome`, internal/agent/localapi `WriteStatus`) was right and is unchanged. What the host holds and when is unchanged too: the same enforce ran right after the reply before.
- Same pattern: `connect` had it as well (fixed, same code as `disconnect`). `kill-switch` and `allow-lan` already waited for the node to act on the toggle (`setToggle`). `connect-on-boot` doesn't move the kill switch. `status`, `diag` and `rollback` change nothing through the node's goroutine.
- Changed output lines (the `kill switch:` line of the printed status; fail-closed-after-crash is on by default; kill switch toggle off). Device checklist rows that read this line need the new text:
  - `thinkpol rules preset everything` (or `all-but-domestic`) while connected or meant up: `kill switch:  off, allow-LAN off` → `kill switch:  off, allow-LAN off (held by the crash posture while the connection is meant up)`.
  - `thinkpol rules preset space` from `everything`/`all-but-domestic` while connected or meant up: `kill switch:  off, allow-LAN off (held by the crash posture while the connection is meant up)` → `kill switch:  off, allow-LAN off`.
  - `thinkpol disconnect` under `everything`/`all-but-domestic`: `kill switch:  off, allow-LAN off (held by the crash posture while the connection is meant up)` → `kill switch:  off, allow-LAN off`.
  - `thinkpol connect` from disconnected under `everything`/`all-but-domestic`: `kill switch:  off, allow-LAN off` → `kill switch:  off, allow-LAN off (held by the crash posture while the connection is meant up)`.
  - With the toggle on the text doesn't change (`on, allow-LAN …  (in place)` before and after). A kill switch that fails to apply or remove now shows `(not enforced: apply_failed, retrying)` / `(not enforced: remove_failed, retrying)` in the change's own output instead of only in a later `status`. Column alignment follows the status's tabwriter as before.
- Tests: `TestAChangeReturnsWithTheKillSwitchItLeaves` (internal/agent) runs the real node with the in-memory kill switch slowed to 300 ms, so a reply ahead of the kill switch loses every time, and checks Status and the host right as each change returns. It runs on Linux and macOS alike with no host tools. The firewall package's fake pfctl is internal to that package, which another ticket owns right now; the fix is in OS-independent node code, so the darwin run with the in-memory kill switch exercises the same path a pf-backed one would.
- A failed apply makes the loop's next turn retry it straight away (`keep` in internal/agent/killswitch.go skips a repeat only while nothing failed), so a hung pfctl stalls the node loop about twice as long per command as before; the status in the reply is honest at the moment it returns.
- Out of scope: `connect`, `disconnect` and `rules preset` still exit 0 when the kill switch they moved failed to apply or remove; only the toggles say `kill_switch_not_enforced`. The printed line now shows it; whether the exit code should too is a separate decision.

## Review findings
- [x] R1.1 internal/agent/node.go SetRulePreset: the "Taken" wait comment now names the kill switch's Apply or Close (pfctl runs on macOS, nftables on Linux) and that the wait ignores ctx.
- [x] R1.2 A failure-path step in TestAChangeReturnsWithTheKillSwitchItLeaves ("failing"): `rules preset everything` while meant up returns with apply_failed, not enforced; `disconnect` with a failing remove returns with remove_failed.
- [x] R1.3 Acceptance box 1 says the in-memory kill switch runs on both OSes, not a fake pfctl.
- [x] R1.4 Docs: internal/agent/doc.go says connect, disconnect and the rule preset return once the kill switch followed; docs/design/api-overview-reference.md Connect/Disconnect/SetRulePreset rows say the kill switch follows, and `rules preset` stores the choice in device.json, not rules.local.
- [x] R1.5 Rewrapped the Connect, Disconnect and SetRulePreset doc comments in internal/agent/node.go.
- [x] R1.6 Notes line: a failed apply is retried at once at the loop's next turn, so a hung pfctl stalls the loop about twice as long per command.
- [x] R2.1 internal/agent/killswitch_test.go "failing" step: after `failWith(nil)` a settings change (`SetAllowLAN`) re-applies the kill switch, so the step doesn't depend on the loop's own retry running after the failure was cleared (else it waits for the 10 s re-apply tick).
- [x] R2.2 internal/agent/doc.go: rewrapped the over-long line in the kill-switch paragraph.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-224
- 2026-11-16 node replies to preset/connect/disconnect after its kill switch follows; test TestAChangeReturnsWithTheKillSwitchItLeaves; mutations (each fails 3/3, passes restored): takeRules without its enforceKillSwitch (preset step fails), runner.request without its enforceKillSwitch (disconnect step fails), awaitSection replying before keepKillSwitch (waiting preset step fails)
- 2026-11-16 at b7a591e3: make lint and make test pass; TestAChangeReturnsWithTheKillSwitchItLeaves passes on Linux (-race, -count=5) and macOS; lab-gotest of ./internal/agent/... and ./cmd/thinkpol/... passes in a lab node
- 2026-11-16 full make lab-test at b7a591e3, first run: failed outside this branch: internal/dataplane/dns TestResolvConfASlowWriterPastTheCapKeepsItsServers (the TP-220 flake; 2 of 5 alone in a lab node; the package doesn't depend on internal/agent) and TestCensorMatrix cells on "waiting for the subnet allocation lock: context deadline exceeded" (machine loaded)
- 2026-11-16 full make lab-test at b7a591e3, re-run: the session lost its output after a long lock wait; the run went on, regenerated lab/RESULTS.md (TestCensorMatrix passed) and tore its labs down, but its exit status is unknown, so the lab-test box stays open
- 2026-11-16 handoff: code and tests done; left: one full make lab-test with a cited exit status (rerun once TP-220 lands, or judge the dns flake as TP-220's), then in-progress → review
- 2026-11-16 review round 1: fix R1.1–R1.6, then the full lab
- 2026-11-16 R1.2 mutations (each fails 3/3 on the new "failing" step, passes restored): takeRules without its enforceKillSwitch (preset returns not active, enforced, no error), runner.request without its enforceKillSwitch (disconnect returns active, enforced, no error)
- 2026-11-16 merged origin/rewrite (TP-221, TP-227); at 2fb1bb87: make lint and make test pass
- 2026-11-16 full make lab-test at 2fb1bb87 started and queued for the full-lab lock behind other branches; no exit status yet
- 2026-11-16 handoff: R1.1–R1.6 done; left: the full make lab-test result at 2fb1bb87 (box 3), then in-progress → review
- 2026-11-16 delta check: merge, nits R2.1–R2.2
- 2026-11-16 at 789ecaa6: make lint passes; TestAChangeReturnsWithTheKillSwitchItLeaves passes -count=20 with busy loops beside it, and once with -race
- 2026-11-16 full make lab-test at 2fb1bb87: exit 2; one failure, TestCensorMatrix/relay-tcp_(reference)/server-hello: the cell's docker compose up hung after starting 3 of 7 containers and was cut off after 608 s ("RESULTS.md not written"; machine loaded); every lab gotest package passed (39), internal/dataplane/dns included. Not the dns flake or the subnet-lock timeout, so box 3 stays open
- 2026-11-16 handoff: nits done; left: judge or re-run the full lab (box 3), then review → done
