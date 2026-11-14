---
id: TP-170
title: "Device keys sealed in the OS keystore (should)"
milestone: later
area: agent
stream: core
repo: thinkpol-vpn
size: M
needs_human: macos
depends_on: []
refs: [RR52, docs/design/security.md#node-safety]
owner: ""
branch: ""
---

## Goal
A should, not a must: a device's private keys are sealed in the OS keystore (Keychain on macOS, DPAPI on Windows) instead of a root-only file, so a copy of the disk alone doesn't yield them.

## Scope
- A key store port with a file adapter (today's behaviour) and keystore adapters for macOS and Windows; Linux stays on the file unless a keystore fits.
- What a seized, unlocked device still gives away, written into RR52.
- docs/design/security.md "Node safety" updated.

## Out of scope
- Server nodes: their keys stay in the state directory.
- Key rotation and revocation: TP-169.

## Acceptance
- [ ] unit tests: the file adapter and a fake keystore behind the same port tests
- [ ] macOS device checklist: after install the key is in the Keychain and not on disk; the node connects after a reboot (results recorded in Notes)
- [ ] RR52 updated
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07.
- owner 2026-11-07: documented now, built after the concept is proven.
- Windows' half waits for the Windows client (M5).

## Log
- 2026-11-07 created in backlog
- 2026-11-07 milestone → later (owner's MVP cut: owner: security later)
