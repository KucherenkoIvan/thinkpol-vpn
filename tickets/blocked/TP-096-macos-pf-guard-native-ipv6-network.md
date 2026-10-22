---
id: TP-096
title: "macOS pf guard on a network with native IPv6"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-078, TP-092]
refs: [DESIGN#ipv6]
needs_human: macos
owner: ""
branch: ""
---

## Goal
On a Mac connected to a network with native IPv6, run TP-078's device checklist steps 0–10: bound `ping6`/`curl -6 --interface en0` refused, tcpdump on en0 clean, still refused after kill -9, clean after stop (`-connect=false`).

## Scope
- Record results in this ticket's Notes (device-test kit session B: checks 08a, 08, 09, 10, plus the leak-path steps that were UNKNOWN without native IPv6 in TP-078 sessions A and B).

## Out of scope
Lab emulation of native IPv6 on the host (host network stack is off limits).

## Acceptance
- [ ] steps 0–10 of TP-078's device checklist pass on a network with global IPv6 and a default IPv6 route, results in Notes
- [ ] TP-126's pfctl parsers, read from pfctl's source, not a Mac (needs no native IPv6): on a stock Mac, run `sudo pfctl -s Interfaces -v` and `sudo pfctl -a com.apple -s Anchors` and save both outputs in Notes; with the guard applied, it reports neither a skipped interface nor an anchor before `000.thinkpol` (health not `ipv6_guard_not_enforced`). Then, still connected, load the stock rules with a skip on a name no interface has, keeping the hook: `(echo 'set skip on lo'; cat /etc/pf.conf) | sudo pfctl -f -`; record whether `sudo pfctl -s Interfaces -v` shows `lo (skip)` (or marks `lo0` instead), and what health says within 10 s; then restore with `sudo pfctl -f /etc/pf.conf`
- [ ] `make lint` and `make test` pass (no code change required if the run is docs-only)

## Blocked by
The owner has no network with native IPv6 available now. Unblock when one is.

## Notes
- The device-test kit's session B (08a, 08, 09, 10) is ready for this run.

## Log
- 2026-10-16 created (TP-078/TP-092 device sessions)
- 2026-10-16 docs: can run in TP-097's VM lab (a router VM gives native IPv6), so it depends on TP-097
- 2026-10-16 docs: TP-097 cancelled; this waits for a network with native IPv6 again
- 2026-10-22 TP-126: an acceptance item for the pfctl listings its bypass check parses (`-s Interfaces -v`, `-a com.apple -s Anchors`)
- 2026-10-22 TP-126 round 2: the `set skip on lo` step keeps the hook (prepended to the stock rules) and records what health says
