---
id: TP-194
title: "netcfg ledger: undo paths keep what a failed revert left"
milestone: later
area: dataplane
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-119]
refs: []
owner: ""
branch: ""
---

## Goal
When an Apply fails AND a revert fails, the ledger's records still describe the interfaces, so Close restores what it set.

## Scope
Three cases from TP-119's delta checks (2026-11-07):
- dropLinkChange's undo restores a snapshot over a failed revert's note.
- adoptLinkChange's undo overwrites whatever is filed under the old name (an altname moved between interfaces plus two failures).
- Two config names for one interface in one Apply give an order-dependent result.

## Out of scope
None named.

## Acceptance
- [ ] a unit test per case with a fake linkOps
- [ ] `make lint`, `make test` pass

## Notes
- Found in TP-119's round-2 and round-3 delta checks, 2026-11-07; all need two failures in a row or an unusual config.

## Log
- 2026-11-07 created in backlog

