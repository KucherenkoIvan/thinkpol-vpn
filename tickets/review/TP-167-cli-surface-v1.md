---
id: TP-167
title: "CLI surface v1: exit codes and the setting shape"
milestone: M2
area: cmd
stream: clients
repo: thinkpol-vpn
size: M
depends_on: []
refs: [D8, docs/design/api-overview.md#verdicts-owner-2026-11-07]
owner: "agent-tp-167"
branch: "tp-167-cli-surface-v1"
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
- [x] a table-driven test runs each command through its cases (success, bad arguments, missing input, service down, permission denied, busy, bad config, partial success) and checks the exit code of each row
  - `TestEveryCommandExitsBySysexits` (cmd/thinkpol/exitcode_unix_test.go): every visible command, the cases that apply to it, and a check that no visible command lacks rows; `TestExitCodeMapsEachFailure` for the mapping itself. Permission and busy rows skip as root (root is never refused), so they run in `make test`, and the lab covers 77. `up`'s busy (75) is lab `TestASecondAgentChangesNothing`; `rollback`'s, lab `TestRollbackPutsTheHostBackAfterACrashAndTheRestartStaysDown` (exit 75, unchanged).
- [x] the kill switch and connect-on-boot each print their value with no argument and set it with one
  - Already the shape since TP-048 and TP-166 (no other forms existed to remove); `TestASettingIsShownWithNoValueAndSetWithOne` (cmd/thinkpol/settings_unix_test.go) proves it: off, on, off, each set, then shown alone.
- [x] lab: `connect` without DNS protection exits 1, prints the status, and names `dns_not_protected` on stderr; `mallory` gets 77
  - `TestTheCLIExitsBySysexits` (lab/cli_exit_test.go): device-b on systemd-resolved with a domain on its physical link; `connect` exits 1 with `state: connected` on stdout and `[dns_not_protected]` on stderr, the tunnel stays up; mallory's status, connect, disconnect, kill-switch and connect-on-boot exit 77 with `[permission_denied]`; with the agent stopped, `status` exits 69.
- [x] `make lint`, `make test`, `make lab-test` pass
  - all three on ea87211 (Log, 2026-11-15).

## Notes
- Source: TP-139 owner session, 2026-11-07. Owner decisions on F4 (sysexits), F5–F7 (naming, "easy to redesign later"); F9–F20 are the suggested verdicts the owner did not object to (docs/design/api-overview.md "Verdicts").
- Split 2026-11-07 (owner's MVP cut): the snake_case sweep (F5), the other flags and settings (F7, `rules preset`), `-json` everywhere (F12), help on stdout (F11), F9, F10, F13, F14, F16, F17, F19, F20 and the CLI reference moved to TP-181. The lab box's "a message that doesn't say only root" went with F9.
- If the kill switch (TP-048) hasn't landed when this starts, its setting gets the shape when TP-048 adds it.

## Log
- 2026-11-07 created in backlog
- 2026-11-07 split (owner's MVP cut): exit codes and the kill-switch/connect-on-boot setting shape stay; the rest → TP-181
- 2026-11-14 backlog → in-progress, owner: agent-tp-167
- 2026-11-14 built: every exit code comes from one ordered table, `exitCodes` and `exitCode` in cmd/thinkpol/exitcode.go; commands return errors, never numbers (`tempFailError` and the 2s are gone). 64 usage, flags and wrong arguments, a removed form (`argsError`), unknown_rule_preset; 66 ENOENT; 69 service_down, not_running; 75 another agent, membership_unknown; 77 permission_denied, root_only, rollback and service install/uninstall not as root (new `service.ErrNeedsRoot`), EACCES/EPERM; 78 agent.ConfigError; else 1. Local API changes go through `writeChange` (cli.go): on exit 1 the current status is printed; run() ends a refusal's stderr line with its code (` [dns_not_protected]`)
- 2026-11-14 decided (implementer, open to the owner): server_mode is 1, not 78; membership_unknown is 75; a missing output directory is 66 (ENOENT can't tell an input from an output). The settings already had the `<setting> [value]` shape (TP-048, TP-166): nothing to replace, and no aliases existed
- 2026-11-14 docs: api-overview.md "TP-167" section (the table, stderr, the status on exit 1, the setting shape), the reference's snapshot note points to it, cmd/thinkpol package doc, agent doc (a second `up` is 75), configuration.md's CLI reference is TP-181's; existing tests moved from 2 to 64 and from 1 to 66/77 where the table says so; lab TestASecondAgentChangesNothing (`up` now 75) and TestLocalAPI (service_down now 69) updated
- 2026-11-14 mutations, unit, all killed: errUsagePrinted not 64; membership_unknown not 75; another agent not 75; service_down not 69; not_running not 69; service.ErrNeedsRoot not 77; ENOENT not 66; ConfigError not 78; unknown_rule_preset not 64; ENOENT checked before the refusals; argsError not 64; no status on exit 1; the status on every failure; no machine code on stderr; no command exits 2; kill-switch and connect-on-boot with no value printing the status; kill-switch set always on; connect-on-boot set ignored; a visible command without rows (the coverage check)
- 2026-11-14 mutations, lab (TestTheCLIExitsBySysexits, lab-gotest), both killed: no status on exit 1; permission refusals not 77. Lab-gotest of TestTheCLIExitsBySysexits, TestASecondAgentChangesNothing and TestLocalAPI green on 39097cf
- 2026-11-14 first full lab (852fe16) failed only in-node: the busy rows ran as root, whom no group check refuses; fixed in a58882e (skip as root, like permission); cmd/thinkpol in a lab node green after
- 2026-11-15 merged origin/rewrite twice (TP-210, TP-208); the reference file kept under 50 KB by folding TP-167's pointer into its snapshot note
- 2026-11-15 ea87211: `make lint` green, `make test` green, full `make lab-test` green (lab phase and 39 in-node packages)
- 2026-11-15 out of scope: internal/dataplane/dns TestResolvConfAFileRenamedInIsTakenAtOnce failed three times in `make test` under load (once on rewrite d2a4793 too), then passed; not touched here, no ticket filed
- 2026-11-15 couldn't verify: `up`'s permission (77) in a unit test (needs another user's state directory); macOS's membership_unknown (75) only through a fake Membership
- 2026-11-15 in-progress → review
