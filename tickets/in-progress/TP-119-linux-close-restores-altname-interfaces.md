---
id: TP-119
title: "Linux netcfg: Close restores an interface configured by an altname"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-102]
refs: [docs/design/routing.md#routing-rules-and-dns]
owner: "agent-tp-119"
branch: "tp-119-linux-close-restores-altname-interfaces"
---

## Goal
An interface the config names by one of its alternative names gets its MTU and up/down state back when the configurator closes, as one named by its kernel name does.

## Scope
- The ledger keys a link record by the config's name. On `Close`, restore looks the link up by index and drops the record when the kernel name differs from the recorded one, so an interface configured through an altname keeps the node's MTU and state after the node is gone. Predates TP-102 (old Linux code did the same); TP-102 fixed the within-Apply half (f25c9f0, `TestAnAltnameKeepsItsChanges`).
- Restore by index, and treat the name check as "is this still the same interface" (index plus one of its names), or record the kernel name alongside the config name.
- Extend `TestAnAltnameKeepsItsChanges` (lab) to assert the MTU and state come back after `Close`.

## Acceptance
- [x] the lab test fails on today's code and passes with the fix
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-102's implementer; filed after TP-102's round-1 review (2026-10-21).

## Log
- 2026-10-21 created in backlog (TP-102 review round 1)
- 2026-11-07 backlog → in-progress, owner: agent-tp-119
- 2026-11-07 fix (2db04ab): a link change records the kernel name with the index; restoreLink takes the interface at that index as the same one while it keeps that name, so an altname-configured interface is restored on Close and when it leaves the config. doc.go says so; export_linux_test.go's ClearFailingClose sets the new field
- 2026-11-07 TestAnAltnameKeepsItsChanges now asserts MTU 1500 and down after the interface leaves the config and after Close: on 56ce3a2's ledger it fails (leaving the config), and with the release half cut it fails at Close; passes with the fix. New TestARenamedInterfaceKeepsItsChanges: a renamed interface keeps the MTU set
- 2026-11-07 mutations (lab): compare the config name again → altname test fails at leaving the config (and at Close with that half cut); drop the name check → rename test fails (mtu 1500, want 1380); all restored
- 2026-11-07 make test green; make lint green up to its last step, vulncheck, which fails on GO-2026-6888 (brotli) and GO-2026-6865 (klauspost/compress), the same on rewrite e6aeb54: pre-existing, out of scope (needs a dependency bump)
- 2026-11-07 make lab-gotest PKG=./internal/dataplane/netcfg/... at 0d08238: 48 pass. Full make lab-test at 0d08238 did not finish: stopped by the agent's 30 min run limit while other tickets' labs ran; by then TestRouteTableSendsOnlyDirectAroundTheTunnel, TestAnotherRunFromTheCheckoutBuildsItsOwnBinaries and TestTCPThroughCensorDrop (lab/) had failed on 600 s timeouts, outside netcfg. Second acceptance box stays open
- 2026-11-07 handoff: stays in in-progress; to finish, run make lab-test on a quiet Docker (no other tplab labs) and get vulncheck green on rewrite, then tick the box and move to review
