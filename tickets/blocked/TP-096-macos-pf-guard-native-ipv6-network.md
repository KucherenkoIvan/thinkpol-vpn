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
- [ ] TP-129's reading of anchors above the hook, from pfctl's and pf's source, not a Mac (needs no native IPv6). Connected, with the guard applied: load the stock rules with an anchor called before the hook, `awk '/^anchor "com.apple\/\*"/{print "anchor \"tp129\" all"}1' /etc/pf.conf | sudo pfctl -f -`, then `printf 'anchor "inner" all\nanchor "/tp129b" all\n' | sudo pfctl -a tp129 -f -` and `echo 'pass out quick inet6 all no state' | sudo pfctl -a tp129/inner -f -`. Save in Notes: `sudo pfctl -s rules`, `sudo pfctl -a tp129 -s rules` (are the nested names listed relative, `inner`, and absolute, `/tp129b`?), `sudo pfctl -a tp129 -s Anchors` (is the child listed by its full path, `tp129/inner`? a listed child that then reads as missing is a bypass to the guard), and `sudo pfctl -a tp129-none -s Anchors; echo "exit $?"` (stderr exactly `Anchor 'tp129-none' not found.`, exit 0?). Record what health says within 10 s (want `ipv6_guard_not_enforced`, and the agent's log naming `anchor tp129/inner`); then `sudo pfctl -a tp129/inner -F rules` and record health again (want enforced). Then `printf 'anchor all {\n pass out all\n}\n' | sudo pfctl -a tp129b -f -` and save `sudo pfctl -a tp129b -s rules` (is an anonymous anchor listed as `anchor all`, without a name, or inline in braces?); health may say not enforced now (an anchor the guard can't name). Restore: `sudo pfctl -a tp129b -F rules`, `sudo pfctl -a tp129 -F rules` and `sudo pfctl -f /etc/pf.conf`
- [ ] `make lint` and `make test` pass (no code change required if the run is docs-only)

## Blocked by
The owner has no network with native IPv6 available now. Unblock when one is.

## Notes
- The device-test kit's session B (08a, 08, 09, 10) is ready for this run.

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
- 2026-10-24: macOS device run; ticked pfctl-listings box (steps 6, 20: no skip line shown, health ok); still open: native-IPv6 steps (no IPv6 network), lint/test box (not run).
- 2026-10-29 TP-129: an acceptance item for the anchors read above the hook (nested names as pfctl lists them, the missing anchor answer of `-s Anchors`)
- 2026-10-29 TP-129 round 1: the anchors item also saves `-a tp129 -s Anchors` (children by full path) and how an anonymous anchor is listed
