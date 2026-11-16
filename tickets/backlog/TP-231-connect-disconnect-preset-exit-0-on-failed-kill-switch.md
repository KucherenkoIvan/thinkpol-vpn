---
id: TP-231
title: "connect, disconnect and rules preset exit 0 when the kill switch they moved failed"
milestone: later
area: cmd/thinkpol
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
Since TP-224 these commands print the kill switch's real state after their change, including "(not enforced: apply_failed, retrying)" or "remove_failed". But they still exit 0 when the kill switch they moved failed to apply or remove; only the kill-switch and allow-LAN toggles return `kill_switch_not_enforced`. A script that checks the exit code doesn't notice.

## Scope
- `connect`, `disconnect` and `rules preset` exit with the toggles' code when the kill switch they moved isn't enforced.

## Out of scope

## Acceptance
- [ ] These commands exit with the same code the toggles use when the kill switch they moved isn't enforced, documented in the API reference and the exit-code table.
- [ ] Tests for each command's failure exit; mutation-checked.

## Notes
- After the MVP (orchestrator default, 2026-11-16; the owner may pull it into M2).

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
