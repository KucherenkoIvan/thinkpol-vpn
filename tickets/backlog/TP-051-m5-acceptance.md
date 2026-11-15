---
id: TP-051
title: "M5 acceptance"
milestone: M5
area: release
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-047, TP-048, TP-049, TP-050, TP-076]
refs: [docs/design/milestones.md#milestones]
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
Open, Windows (from [windows.md](../../docs/design/windows.md), review round 1): the M5 binary is unsigned. A downloaded one carries the Mark of the Web, so SmartScreen shows "Windows protected your PC" and UAC an unknown publisher; Defender sometimes flags Go binaries (Go FAQ, <https://go.dev/doc/faq#virus>); Smart App Control, when on, blocks unsigned binaries with no "Run anyway". Options: EV no longer bypasses SmartScreen; Azure Artifact Signing (about $10/month) builds reputation like OV and is open to individuals in few countries (<https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options>, <https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation>); SignPath Foundation signs open source free (<https://signpath.org/>), and applying early buys lead time. The package also decides whether `wintun.dll` ships beside the binary (windows.md question 12 d) and how a terminal-free install calls `service install`.

## Log
- 2026-10-10 created in backlog
- 2026-10-15 docs (backlog grooming): daily-use metric removed (starts after M2); depends on TP-076
