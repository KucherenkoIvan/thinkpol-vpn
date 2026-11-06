---
id: TP-168
title: "`status` is local, `diag` checks over the network; one JSON convention"
milestone: M2
area: cmd
repo: thinkpol-vpn
size: M
depends_on: []
refs: [S1, docs/design/api-overview.md#verdicts-owner-2026-11-07, docs/design/desktop-client.md#the-local-api]
owner: ""
branch: ""
---

## Goal
`status` and `diag` do different jobs (TP-139 findings F3, F12). `status` is the service's local state, fast and with no network access. `diag` diagnoses deeper over the network and produces a report that can be shared because it reveals nothing private. Both speak one JSON convention, so the device harness, lab verdicts and later the tray parse one shape.

## Scope
- **`status`:** interface, spaces, links and their state, health, toggles, from the service's state only. No network access.
- **`diag`:** active checks over the network: DNS through the tunnel, peers, path MTU, a leak check, the guard. A status snapshot is one section of its report, taken from the same code as `status`, not computed a second way.
- **Redaction:** `diag`'s report reveals no private information (no keys, secrets, member names; public addresses only where the design already allows them in root's host parts, or redacted). Write down what is redacted and why in the `localapi` package doc.
- **One JSON convention** for both: snake_case field names, every field present, `schema_version`, opt-in with `-json`. Human output stays text; `diag` gains a text form. Write the convention down (the `localapi` package doc) and say which part is the v1 contract.
- docs/design/api-overview-reference.md updated for both commands.

## Out of scope
- `-json` on the other commands: TP-167, using this convention.
- `diag` without a running agent: TP-133.
- User-defined diag scripts: TP-171.

## Acceptance
- [ ] unit test: `status -json` and `diag -json`'s status section are the same bytes for the same state (field names snake_case, zero values present, `schema_version` set)
- [ ] unit test: `status` makes no network call (a test transport that fails any dial)
- [ ] lab: `diag` on a connected device reports DNS through the tunnel, its peers, the path MTU, the leak check and the guard; on a broken tunnel it names the failing check
- [ ] lab: a `diag` report searched for the node's keys, the space's secrets and member names finds none
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07 (owner decision on F3 and F12; docs/design/api-overview.md "Verdicts").
- Overlaps TP-133 (`diag` without a running agent): TP-133's new `agent` field follows this convention; whichever starts second merges the other first.
- TP-167 adds `-json` elsewhere in this convention; whichever lands first writes the shared output code.
- After the MVP, to be decided: user-defined diag scripts over an SDK (TP-171).

## Log
- 2026-11-07 created in backlog
