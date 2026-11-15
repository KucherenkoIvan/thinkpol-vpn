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
- [ ] Both commands print the kill switch's post-change state; tests on Linux and on macOS (fake pfctl, no real host tools) that fail on the old output.
- [ ] Any other command with the same pattern fixed or listed in Notes with why not.
- [ ] Mutation-checked; `make lint`, `make test`, `make lab-test` pass.

## Notes
- This changes what macOS prints, so it lands before the M2 device session.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-224
