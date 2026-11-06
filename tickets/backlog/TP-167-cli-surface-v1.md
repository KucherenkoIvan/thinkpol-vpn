---
id: TP-167
title: "CLI surface v1: exit codes and the setting shape"
milestone: M2
area: cmd
repo: thinkpol-vpn
size: M
depends_on: []
refs: [D8, docs/design/api-overview.md#verdicts-owner-2026-11-07]
owner: ""
branch: ""
---

## Goal
Before M2 adds the kill-switch setting, scripts can branch on the CLI's exit codes, and the kill switch and connect-on-boot are shown and set the same way (TP-139 findings F4, F6).

## Scope
- **Exit codes (F4):** BSD `sysexits.h` on every command, as in the verdicts' table: 0 the requested state was reached; 1 not reached, even when it failed closed, with the status still printed; 64 bad arguments (Go's flag default 2 maps to 64); 66 a named input is missing; 69 the service isn't running; 75 busy, try again (e.g. the host lock is held); 77 permission denied; 78 bad configuration. `connect` up without DNS protection exits 1, prints the status and names the machine code on stderr.
- **Setting shape (F6):** `<setting> [value]` for the kill switch and connect-on-boot: no value shows it, a value sets it.

## Out of scope
- `status` versus `diag` and the JSON convention itself: TP-168.
- New settings (kill switch, ceiling): TP-048, TP-111, which follow these rules.
- Renaming commands that are verbs or nouns today (`up`, `connect`, `status`): the verdict keeps them.
- The snake_case sweep, `-json` everywhere, help on stdout, the remaining F-items and the CLI reference: TP-181 (after the MVP).

## Acceptance
- [ ] a table-driven test runs each command through its cases (success, bad arguments, missing input, service down, permission denied, busy, bad config, partial success) and checks the exit code of each row
- [ ] the kill switch and connect-on-boot each print their value with no argument and set it with one
- [ ] lab: `connect` without DNS protection exits 1, prints the status, and names `dns_not_protected` on stderr; `mallory` gets 77
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07. Owner decisions on F4 (sysexits), F5–F7 (naming, "easy to redesign later"); F9–F20 are the suggested verdicts the owner did not object to (docs/design/api-overview.md "Verdicts").
- Split 2026-11-07 (owner's MVP cut): the snake_case sweep (F5), the other flags and settings (F7, `rules preset`), `-json` everywhere (F12), help on stdout (F11), F9, F10, F13, F14, F16, F17, F19, F20 and the CLI reference moved to TP-181. The lab box's "a message that doesn't say only root" went with F9.
- If the kill switch (TP-048) hasn't landed when this starts, its setting gets the shape when TP-048 adds it.

## Log
- 2026-11-07 created in backlog
- 2026-11-07 split (owner's MVP cut): exit codes and the kill-switch/connect-on-boot setting shape stay; the rest → TP-181
