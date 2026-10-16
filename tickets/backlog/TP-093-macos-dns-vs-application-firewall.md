---
id: TP-093
title: "macOS: the device's resolver behind the Application Firewall"
milestone: M2
area: dataplane/dns
repo: thinkpol-vpn
size: M
depends_on: [TP-019]
refs: [DESIGN#dns]
needs_human: macos
owner: ""
branch: ""
---

## Goal
DNS through the tunnel works on a Mac with the Application Firewall on, Block-all included. There is no "accept incoming connections?" prompt, on the first connect or after an update, and a resolver nobody can reach shows in the health instead of failing silently.

## Scope
- On macOS, the resolver the OS is pointed at listens on a loopback address, not the device's overlay address. The Application Firewall filters incoming connections to apps but not loopback traffic. Pick the address (127.0.0.x, ::1) and say why in DESIGN.md. Keep the overlay address where other nodes need to reach it.
- A health problem when the OS is pointed at the resolver but no query reaches it for a while. The probe must not count its own queries: the agent queries itself through the OS path and expects the query to arrive.
- DESIGN.md: the resolver's address on macOS and why.

## Out of scope
- Code signing and installing a firewall exception (TP-046 decides whether its installer needs one once this lands).

## Acceptance
- [ ] the macOS supplemental resolver names a loopback address; unit tests on the configurator
- [ ] the health problem has a test with a resolver that receives nothing
- [ ] device: with the firewall and Block-all on, DNS through the tunnel works and macOS asks nothing

## Notes
- **Device evidence (2026-10-16, TP-078 session A, check 07).** The owner turned on the firewall and Block-all, and macOS asked whether thinkpol may accept incoming connections. Until the owner answered, every query failed: `dig @<overlay address>` timed out, and so did the system resolver and the overlay names. After Allow, a second run passed and macOS didn't ask again. The allowed-app entry is tied to the binary's code signature, so an ad-hoc-signed build asks again after every update.
- Not known: whether Block-all itself lets an allowed app's listener through (macOS normally doesn't prompt under Block-all). Moving to loopback makes it irrelevant.

## Log
- 2026-10-16 created in backlog (TP-078 device session A)
