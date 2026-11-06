---
id: TP-181
title: "CLI surface: naming, -json everywhere, help, the remaining F-items, CLI reference"
milestone: later
area: cmd
repo: thinkpol-vpn
size: L
depends_on: [TP-167]
split_from: TP-167
refs: [D8, docs/design/api-overview.md#verdicts-owner-2026-11-07]
owner: ""
branch: ""
---

## Goal
The rest of the CLI's one set of rules: machine codes are spelled one way, every setting and flag follows one shape, every command that prints a status or a list has a machine form, and the CLI has a reference (TP-139 findings F5, F7, F9–F14, F16, F17, F19, F20).

## Scope
- **Naming (F5):** machine codes and enumerated values snake_case everywhere: rename `route-table` (a route's owner in `diag`) to `route_table` and `inbound link` (a skip item) to `inbound_link`. Human text uses words; presets and flags stay kebab-case.
- **Setting shape (F6), the rest:** `<setting> [value]` for every other setting. `rules preset` with no argument prints the current preset.
- **Flags (F7):** toggles take `on|off`; plain booleans only for output switches (`-json`, `-f`). `-socket` everywhere, with `up -api-socket` kept as an alias. `-out` everywhere, with `diag -o` kept as an alias. `up -h` shows flag types as the other commands do.
- **`-json` (F12)** on every command that prints a status or a list (`connect`, `disconnect`, `rules preset`, `spaces`, `service connect-on-boot` or its replacement), in TP-168's JSON convention.
- **F9:** the refusal message is worded per call, or generic ("your user may not do that: …"), never "only root may do that" for a member.
- **F10:** usage errors print one line saying what was wrong before the synopsis; drop the `config: validation:` prefix.
- **F11:** asked-for help (`help`, `-h`, `-help`, `--help`) goes to stdout with exit 0; usage errors stay on stderr.
- **F13:** `Connect` and `SetRulePreset` return the status together with the warning, so clients show both (a proto change).
- **F14:** `up -log-level`'s help says the lines also reach the ring `thinkpol logs` reads; `diag`'s summary is rewritten to be readable.
- **F16:** `re-applied 1 time`; a server's `uplink:` line aligned; the two `udp` listeners tell IPv4 from IPv6.
- **F17:** `service uninstall` prints "the group thinkpol stays" only when the group exists (exit 0 stays).
- **F19:** `dev lists build -only` counts the source's other lists.
- **F20:** `rules.local` written 0600.
- The CLI reference: docs/design/api-overview-reference.md updated to match, or a dedicated CLI reference generated from the commands; README links whichever is the reference.

## Out of scope
- Exit codes and the kill-switch and connect-on-boot setting shape: TP-167.

## Acceptance
- [ ] a test greps every machine code and enumerated value the CLI and `diag` can print and fails on one that isn't snake_case
- [ ] `rules preset` with no argument prints the preset; `thinkpol status -h | less` shows help (stdout); a usage error names what was wrong
- [ ] `connect`, `disconnect`, `rules preset`, `spaces` accept `-json`; `diag -out` and `up -socket` work, and the aliases still do
- [ ] lab: `mallory` gets a message that doesn't say "only root"
- [ ] the CLI reference is regenerated or updated, and README links it
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Split from TP-167, 2026-11-07, owner's MVP cut.
- Source: TP-139 owner session, 2026-11-07 (docs/design/api-overview.md "Verdicts").
- F16's fourth item (`health: ok` with a peer at `no path yet`) is TP-140's.
- TP-168 defines the JSON convention; this ticket reuses its output code.
- F20's item is moot if TP-166 has replaced `rules.local` by the time this starts.

## Log
- 2026-11-07 created in backlog (split from TP-167)
