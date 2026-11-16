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
- [x] Both commands print the kill switch's post-change state; tests on Linux and on macOS (fake pfctl, no real host tools) that fail on the old output.
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
- Out of scope: `connect`, `disconnect` and `rules preset` still exit 0 when the kill switch they moved failed to apply or remove; only the toggles say `kill_switch_not_enforced`. The printed line now shows it; whether the exit code should too is a separate decision.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-224
- 2026-11-16 node replies to preset/connect/disconnect after its kill switch follows; test TestAChangeReturnsWithTheKillSwitchItLeaves; mutations (each fails 3/3, passes restored): takeRules without its enforceKillSwitch (preset step fails), runner.request without its enforceKillSwitch (disconnect step fails), awaitSection replying before keepKillSwitch (waiting preset step fails)
- 2026-11-16 at b7a591e3: make lint and make test pass; TestAChangeReturnsWithTheKillSwitchItLeaves passes on Linux (-race, -count=5) and macOS; lab-gotest of ./internal/agent/... and ./cmd/thinkpol/... passes in a lab node
- 2026-11-16 full make lab-test at b7a591e3, first run: failed outside this branch: internal/dataplane/dns TestResolvConfASlowWriterPastTheCapKeepsItsServers (the TP-220 flake; 2 of 5 alone in a lab node; the package doesn't depend on internal/agent) and TestCensorMatrix cells on "waiting for the subnet allocation lock: context deadline exceeded" (machine loaded)
- 2026-11-16 full make lab-test at b7a591e3, re-run: the session lost its output after a long lock wait; the run went on, regenerated lab/RESULTS.md (TestCensorMatrix passed) and tore its labs down, but its exit status is unknown, so the lab-test box stays open
- 2026-11-16 handoff: code and tests done; left: one full make lab-test with a cited exit status (rerun once TP-220 lands, or judge the dns flake as TP-220's), then in-progress → review
