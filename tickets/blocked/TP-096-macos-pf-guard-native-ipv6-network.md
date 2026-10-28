---
id: TP-096
title: "macOS pf guard on a network with native IPv6"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-078, TP-092]
refs: [docs/design/security.md#ipv6]
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
- [x] TP-126's pfctl parsers, read from pfctl's source, not a Mac (needs no native IPv6): on a stock Mac, run `sudo pfctl -s Interfaces -v` and `sudo pfctl -a com.apple -s Anchors` and save both outputs in Notes; with the guard applied, it reports neither a skipped interface nor an anchor before `000.thinkpol` (health not `ipv6_guard_not_enforced`). Then, still connected, load the stock rules with a skip on a name no interface has, keeping the hook: `(echo 'set skip on lo'; cat /etc/pf.conf) | sudo pfctl -f -`; record whether `sudo pfctl -s Interfaces -v` shows `lo (skip)` (or marks `lo0` instead), and what health says within 10 s; then restore with `sudo pfctl -f /etc/pf.conf` (device 2026-10-24, steps 6, 20)
- [ ] `make lint` and `make test` pass (no code change required if the run is docs-only)

## Blocked by
The owner has no network with native IPv6 available now. Unblock when one is.

## Notes
- The device-test kit's session B (08a, 08, 09, 10) is ready for this run.
- 2026-10-23 (TP-082): the second acceptance item's pfctl listings and its `set skip on lo` step now run through the device-test harness: `devicetest run TP-096` (plan `lab/devicetest/plans/tp096.go`; `devicetest plans TP-096` prints every step). It records the stock listings, loads `set skip on lo` before the stock rules, records `-s Interfaces -v` and the main rules, loads the stock rules back, records them again, and compares pf with its baseline. The listings with the guard applied, and what health says within 10 s, need a connected agent, so they wait for the harness's exit driver. Steps 0–10 still need a network with native IPv6.

### Device run 2026-10-24: pfctl listings

Commands as recorded: step 1 (stock, before connecting) ran
`sudo pfctl -a com.apple -s Anchors` and `sudo pfctl -s Interfaces -v`; step 6
(guard applied) ran the same two with stderr kept apart (only the "No ALTQ
support in kernel" noise went there).

`pfctl -a com.apple -s Anchors`, step 1 and step 6 (identical):

```
  com.apple/000.thinkpol
  com.apple/200.AirDrop
  com.apple/250.ApplicationFirewall
```

`pfctl -s Interfaces -v`, step 1 and step 6 (identical), one name per line in
the original, compacted here:

```
ALL anpi0 anpi1 ap1 awdl0 bridge0 en0 en1 en2 en3 en4 gif0 llw0 lo0 stf0
utun0–utun30
```

Even with `-v` the listing has no per-interface flags: every line is a bare
name, with no `(skip)` marker and no counters. Before and after (steps 1 and
6) are identical, for both listings.

Step 20 (`(echo 'set skip on lo'; cat /etc/pf.conf) | sudo pfctl -f -`): the
listing was byte-identical to the one above, with no `lo (skip)` and no marked
`lo0`. There is no health snapshot inside 10 s (the first was taken at 20 s);
health read `health: ok` at 20 s and at 77 s (`HEALTH_LEVEL_OK`), the guard
log had no warns, and the restore with `sudo pfctl -f /etc/pf.conf` was clean.

## Log
- 2026-10-16 created (TP-078/TP-092 device sessions)
- 2026-10-16 docs: can run in TP-097's VM lab (a router VM gives native IPv6), so it depends on TP-097
- 2026-10-16 docs: TP-097 cancelled; this waits for a network with native IPv6 again
- 2026-10-22 TP-126: an acceptance item for the pfctl listings its bypass check parses (`-s Interfaces -v`, `-a com.apple -s Anchors`)
- 2026-10-22 TP-126 round 2: the `set skip on lo` step keeps the hook (prepended to the stock rules) and records what health says
- 2026-10-23 docs: its pfctl listings and the `set skip on lo` step run through the device-test harness (TP-082)
- 2026-10-24: macOS device run; ticked pfctl-listings box (steps 6, 20: no skip line shown, health ok); still open: native-IPv6 steps (no IPv6 network), lint/test box (not run).
