---
id: TP-119
title: "Linux netcfg: Close restores an interface configured by an altname"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-102]
refs: [docs/design/routing.md#routing-rules-and-dns]
owner: ""
branch: ""
---

## Goal
An interface the config names by one of its alternative names gets its MTU and up/down state back when the configurator closes, as one named by its kernel name does.

## Scope
- The ledger keys a link record by the config's name. On `Close`, restore looks the link up by index and drops the record when the kernel name differs from the recorded one, so an interface configured through an altname keeps the node's MTU and state after the node is gone. Predates TP-102 (old Linux code did the same); TP-102 fixed the within-Apply half (f25c9f0, `TestAnAltnameKeepsItsChanges`).
- Restore by index, and treat the name check as "is this still the same interface" (index plus one of its names), or record the kernel name alongside the config name.
- Extend `TestAnAltnameKeepsItsChanges` (lab) to assert the MTU and state come back after `Close`.

## Acceptance
- [ ] the lab test fails on today's code and passes with the fix
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-102's implementer; filed after TP-102's round-1 review (2026-10-21).

## Log
- 2026-10-21 created in backlog (TP-102 review round 1)
