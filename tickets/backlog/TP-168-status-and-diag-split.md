---
id: TP-168
title: "`status -json` with `schema_version`"
milestone: M2
area: cmd
repo: thinkpol-vpn
size: S
depends_on: []
refs: [S1, docs/design/api-overview.md#verdicts-owner-2026-11-07, docs/design/desktop-client.md#the-local-api]
owner: ""
branch: ""
---

## Goal
`status` has a machine form the device harness, lab verdicts and later the tray can parse: the service's local state, fast and with no network access, in one JSON convention (TP-139 finding F12; F3's `status` half).

## Scope
- **`status`:** interface, spaces, links and their state, health, toggles, from the service's state only. No network access.
- **One JSON convention:** snake_case field names, every field present, `schema_version`, opt-in with `-json`. Human output stays text. Write the convention down (the `localapi` package doc) and say which part is the v1 contract.
- docs/design/api-overview-reference.md updated for `status`.

## Out of scope
- `-json` on the other commands: TP-181, using this convention.
- `diag` without a running agent: TP-133.
- User-defined diag scripts: TP-171.
- `diag`'s network checks, its redaction and the shareable report: TP-182 (after the MVP).

## Acceptance
- [ ] unit test: `status -json` has snake_case field names, zero values present and `schema_version` set
- [ ] unit test: `status` makes no network call (a test transport that fails any dial)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07 (owner decision on F3 and F12; docs/design/api-overview.md "Verdicts").
- Overlaps TP-133 (`diag` without a running agent): TP-133's new `agent` field follows this convention; whichever starts second merges the other first.
- TP-181 adds `-json` elsewhere in this convention and reuses this ticket's output code.
- After the MVP, to be decided: user-defined diag scripts over an SDK (TP-171).
- This ticket stays on the MVP path only if TP-086 has the tray parse the CLI rather than the local API (open, 2026-11-07).
- Split 2026-11-07 (owner's MVP cut): the network-reaching `diag` and the redacted report moved to TP-182.

## Log
- 2026-11-07 created in backlog
- 2026-11-07 split (owner's MVP cut): `status -json` stays; the network-reaching diag and the redacted report → TP-182
