---
id: TP-142
title: "macOS: the agent exits 2 on its first start at boot under connect-on-boot"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
needs_human: macos
depends_on: [TP-141, TP-144]
refs: [docs/design/security.md#kill-switch]
owner: ""
branch: ""
---

## Goal
The crash on the agent's first start at boot, with connect-on-boot on, is found and fixed, or shown to be something other than thinkpol, with a test that would catch it again.

## Scope
- Read the crash trace TP-141 keeps, from TP-144's device re-run (the connect-on-boot reboot).
- Find the cause, fix it, and add a unit or lab test that reproduces it.
- If the re-run doesn't crash, say so here with the run's evidence, and decide with the owner whether to keep the ticket open for the next device run or close it.

## Out of scope
- Keeping the trace: TP-141.
- The missing-hook boot retry (TP-046's open box): a separate question; this run had the hook loaded before the first Apply.

## Acceptance
- [ ] the cause is named in Notes, with the trace
- [ ] a test reproduces it and passes with the fix
- [ ] device: the connect-on-boot reboot shows `runs = 1` (no crash) under launchctl
- [ ] `make lint`, `make test` pass

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 3): done before the M2 lanes start; TP-048's crash posture is built on this boot path.
- **Device evidence (the 2026-10-24 macOS device run, the connect-on-boot reboot).** launchctl showed `runs = 2`, `last exit code = 2`. The first start (about 25 s after boot) took the pf reference and crashed after the guard's `enable`, so its Close never ran; the second start, ThrottleInterval (5 s) later, adopted the token. Wi-Fi had no link during that boot (`dial failed … no default route (IPv4)`), which may be part of the trigger.
- `up` returns 2 only for usage errors (`cmd/thinkpol/cli.go`), so a Go panic or runtime fatal error is the likely cause. The plist's arguments are fixed.
- Depends on TP-141 (the trace) and TP-144 (the run that records it).

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run, connect-on-boot reboot: before-M2 list)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 3)
