---
id: TP-051
title: "M5 acceptance"
milestone: M5
area: release
repo: thinkpol-vpn
size: M
depends_on: [TP-047, TP-048, TP-049, TP-050, TP-076]
refs: [DESIGN#milestones]
needs_human: person
owner: ""
branch: ""
---

## Goal
The MVP is usable by someone who isn't the author.

## Scope
- Installable packages for macOS, Linux and Windows.
- A non-technical member joins from an invite without a terminal (a real person, not a test).

## Acceptance
- [ ] hand-off test passed and written up in Notes

## Notes
Open: macOS Gatekeeper wants a Developer ID-signed, notarized app; unsigned builds need a manual "open anyway". Decide before this ticket starts.

## Log
- 2026-10-10 created in backlog
- 2026-10-15 docs (backlog grooming): daily-use metric removed (starts after M2); depends on TP-076
