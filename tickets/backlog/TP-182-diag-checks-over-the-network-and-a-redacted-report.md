---
id: TP-182
title: "`diag` checks over the network; a redacted report"
milestone: later
area: cmd
stream: core
repo: thinkpol-vpn
size: M
depends_on: [TP-168]
split_from: TP-168
refs: [S1, docs/design/api-overview.md#verdicts-owner-2026-11-07]
owner: ""
branch: ""
---

## Goal
`diag` diagnoses deeper over the network and produces a report that can be shared because it reveals nothing private (TP-139 finding F3's `diag` half). It speaks TP-168's JSON convention.

## Scope
- **`diag`:** active checks over the network: DNS through the tunnel, peers, path MTU, a leak check, the guard. A status snapshot is one section of its report, taken from the same code as `status`, not computed a second way.
- **Redaction:** `diag`'s report reveals no private information (no keys, secrets, member names; public addresses only where the design already allows them in root's host parts, or redacted). Write down what is redacted and why in the `localapi` package doc.
- `diag -json` in TP-168's convention; `diag` gains a text form.
- docs/design/api-overview-reference.md updated for `diag`.

## Out of scope
- `status -json` and the JSON convention: TP-168.
- `diag` without a running agent: TP-133.

## Acceptance
- [ ] unit test: `status -json` and `diag -json`'s status section are the same bytes for the same state
- [ ] lab: `diag` on a connected device reports DNS through the tunnel, its peers, the path MTU, the leak check and the guard; on a broken tunnel it names the failing check
- [ ] lab: a `diag` report searched for the node's keys, the space's secrets and member names finds none
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Split from TP-168, 2026-11-07, owner's MVP cut.

## Log
- 2026-11-07 created in backlog (split from TP-168)
