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
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-102's implementer; filed after TP-102's round-1 review (2026-10-21).

## Review findings
Round 1, accepted by the orchestrator.
- [x] R1.1 (should-fix, regression from this branch) ledger.go release with restoreLink: a config that switches an interface between its altname and its kernel name (either way, or one altname to another) between Applies makes release restore the interface while the config still wants it (Apply {overlay-alt, 1380, Up}; Apply {ovl0, 1380, Up} ends 1500 and down). Judge "left the config" by interface index; lab test for both directions.
- [x] R1.2 (should-fix) configureLink and updateLinkChange never refresh the recorded kernel name: Apply {overlay-alt, 1380}; down; rename ovl0 to ovl1; Apply again; Close leaves 1380. Refresh kname when configureLink re-finds the same index under the config's name (undone by a failed Apply); lab test; doc.go states the rename limit precisely.
- [x] R1.3 (nit) netcfg_linux_test.go: TestAnAltnameKeepsItsChanges' comment covers the restore on leaving the config and on Close; TestARenamedInterfaceKeepsItsChanges becomes TestARenamedInterfaceIsLeftAlone with a comment claiming only what it checks.

Round 2, accepted by the orchestrator (delta check of round 1).
- [x] R2.1 (should-fix, regression from round 1) ledger.go adoptLinkChange moves a record to whatever name now sits at the same index, so a new interface at a reused index takes over a dead interface's record (Apply {a, 1380, Up}; delete a; create b at the same index, already 1380 and up; Apply {b, 1380, Up}: Close sets b to 1500 and down). Adopt a record from another name only if its recorded kernel name equals the interface's current kernel name, else drop it without restoring; lab test with a new interface at the reused index.
- [x] R2.2 (nit) adoptLinkChange's undo restores a snapshot, overwriting the note a failed revert keeps: move whatever is under the new name back to the old name and restore only the old kernel name.

Round 3, accepted by the orchestrator (delta check of round 2).
- [ ] R3.1 (should-fix) ledger.go adoptLinkChange's undo, rename-only case (same name, new kernel name): it puts the old kernel name back, so after a failed Apply whose MTU revert fails Close sees the current name differ from the recorded one, drops the record and leaves the MTU set forever. The undo keeps the refreshed kernel name and only moves the record back when the names differ; the internal test's renamed case expects the refreshed kname.

## Log
- 2026-10-21 created in backlog (TP-102 review round 1)
- 2026-11-07 backlog → in-progress, owner: agent-tp-119
- 2026-11-07 fix (2db04ab): a link change records the kernel name with the index; restoreLink takes the interface at that index as the same one while it keeps that name, so an altname-configured interface is restored on Close and when it leaves the config. doc.go says so; export_linux_test.go's ClearFailingClose sets the new field
- 2026-11-07 TestAnAltnameKeepsItsChanges now asserts MTU 1500 and down after the interface leaves the config and after Close: on 56ce3a2's ledger it fails (leaving the config), and with the release half cut it fails at Close; passes with the fix. New TestARenamedInterfaceKeepsItsChanges: a renamed interface keeps the MTU set
- 2026-11-07 mutations (lab): compare the config name again → altname test fails at leaving the config (and at Close with that half cut); drop the name check → rename test fails (mtu 1500, want 1380); all restored
- 2026-11-07 make test green; make lint green up to its last step, vulncheck, which fails on GO-2026-6888 (brotli) and GO-2026-6865 (klauspost/compress), the same on rewrite e6aeb54: pre-existing, out of scope (needs a dependency bump)
- 2026-11-07 make lab-gotest PKG=./internal/dataplane/netcfg/... at 0d08238: 48 pass. Full make lab-test at 0d08238 did not finish: stopped by the agent's 30 min run limit while other tickets' labs ran; by then TestRouteTableSendsOnlyDirectAroundTheTunnel, TestAnotherRunFromTheCheckoutBuildsItsOwnBinaries and TestTCPThroughCensorDrop (lab/) had failed on 600 s timeouts, outside netcfg. Second acceptance box stays open
- 2026-11-07 handoff: stays in in-progress; to finish, run make lab-test on a quiet Docker (no other tplab labs) and get vulncheck green on rewrite, then tick the box and move to review
- 2026-11-07 finisher: merged rewrite 7852af8 (head c66ccc8) in as 4c1bfef; make lint green (vulncheck clean after TP-175), make test green
- 2026-11-07 finisher: full make lab-test passed on 4c1bfef (LAB_P=4, run alone): lab/ packages ok, gotest ok for 36 packages, netcfg included; second acceptance box ticked
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.1-R1.3)
- 2026-11-07 fix round 1 (2ba3949): configureLink's new adoptLinkChange files the record of the interface at the found index under the config's name, moving it from another of its names and taking the kernel name afresh (undone by a failed Apply), so a name switch no longer restores a wanted interface (R1.1) and a renamed interface re-found through an altname is restored on Close (R1.2); doc.go states the rename limit as "a rename the configurator never re-finds keeps what was set"
- 2026-11-07 tests (lab): new TestAnInterfaceKeepsItsChangesUnderAnotherName (overlay-alt→ovl0, ovl0→overlay-alt, overlay-alt→overlay-alt2: stays 1380 and up, Close gives 1500 and down) and TestARenamedInterfaceFoundAgainIsRestored (down, rename ovl0→ovl1, Apply again: Close gives 1500 and down); TestAnAltnameKeepsItsChanges' comment covers leaving the config and Close; TestARenamedInterfaceKeepsItsChanges renamed TestARenamedInterfaceIsLeftAlone with a comment claiming only the MTU it checks (R1.3)
- 2026-11-07 mutations (lab): drop the adoptLinkChange call → both new tests fail; skip the search under other names → the name-switch test fails (all three cases, mtu 1500 after the second Apply); skip the kname refresh → the re-found rename test fails (ovl1 keeps 1380 and up after Close); all restored. The undo of the move in a failed Apply has no test of its own
- 2026-11-07 merged rewrite as c955f12; make lint and make test green there; make lab-gotest netcfg green at 2ba3949; full make lab-test passed on c955f12 (LAB_P=4, run alone): lab/ packages ok, gotest ok for 36 packages
- 2026-11-07 has-errors → review
- 2026-11-07 review → has-errors (round 2 findings R2.1-R2.2)
- 2026-11-07 fix round 2 (3adaca0): adoptLinkChange moves a record found under another name only while the interface has the recorded kernel name, else drops it unrestored (a new interface at a reused index is not the old one) (R2.1); its undo moves whatever is under the new name back and restores only the old kernel name, so a failed revert's note stays (R2.2); doc.go says so. The agent that wrote it was paused before logging; a continuation agent re-read the diff against the brief
- 2026-11-07 tests: new TestANewInterfaceAtAReusedIndexIsNotTheOldOne (lab; ovl0 deleted, ovl1 made at its index with `ip link add … index`, already 1380 and up / 9000 and down: Close leaves it as it was before any Apply); new TestAFailedRevertKeepsItsNoteWhenTheRecordMovesBack (ledger_internal_test.go, fake linkOps, darwin and linux: a failed Apply whose MTU revert fails leaves the record under the old name and kernel name with the MTU left on the interface, for a switch to an altname and for a rename refresh) (cd5b5d8)
- 2026-11-07 mutations: drop the kernel-name check (lab) → the reused-index test fails in both cases (Close sets mtu 1500); round 1's snapshot undo → the failed-revert test fails in both cases (mtu 1380 noted, interface at 1400); undo without restoring the kernel name → its renamed case fails; all restored. make lab-gotest netcfg green at 3caf75f (all R1 tests pass too)
- 2026-11-07 merged rewrite b1930a9 as 88d530c; make lint and make test green there
- 2026-11-07 full make lab-test at 88d530c (LAB_P=1, machine loaded, other labs running) stopped at the 30 min limit: lab/ packages ok, node gotest ok through netcfg, then internal/dataplane/path failed TestBindDropsWhatWireGuardCantHold and TestTrafficSticksToOneLinkPerNeighbour (delivery timeouts; this branch doesn't touch path); re-run under the exclusive CPU lock
- 2026-11-07 full make lab-test re-run at dcce1b9 under the exclusive CPU lock (LAB_P=4): lab/ packages ok, gotest ok for 36 packages (path included, so the earlier failures were load); this re-run was backgrounded by the harness after 10 min and waited on, not polled
- 2026-11-07 has-errors → review
- 2026-11-07 review → has-errors (round 3 finding R3.1)
