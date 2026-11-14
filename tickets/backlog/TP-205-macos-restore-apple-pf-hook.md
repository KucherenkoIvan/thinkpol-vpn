---
id: TP-205
title: "macOS: put Apple's pf hook back after the main ruleset is flushed"
milestone: M3
area: dataplane/firewall
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-048]
refs: [D4, RR58]
needs_human: macos
owner: ""
branch: ""
---

## Goal
On macOS, after something flushes the main ruleset (`pfctl -F all`, another VPN loading a pf.conf without `anchor "com.apple/*"`), the kill switch is enforced again within a re-apply, without a reboot. Today the anchor hangs under Apple's hook; with the hook gone nothing of it is evaluated and status says `kill_switch_not_enforced` until someone puts the hook back (RR58).

## Scope
- When Apply finds the hook missing, restore it without discarding what the other owner loaded, or say exactly why that can't be done safely and what the agent does instead.
- The same for the IPv6 guard, which hangs under the same hook, if the mechanism is shared.
- docs: firewall doc.go, security.md, RR58.

## Out of scope
- Reloading /etc/pf.conf wholesale (decided against in TP-048's review, R2.5: it would discard another owner's rules).
- Fighting another tool that keeps flushing pf: detect and report, don't loop.

## Acceptance
- [ ] the main ruleset flushed, the next Apply has the anchor evaluated again (unit test with the fake pfctl, mutation-checked)
- [ ] another owner's rules in the main ruleset survive the restore (unit test)
- [ ] device check row: `sudo pfctl -F all` with the kill switch on, traffic confined again within about 15 s (TP-029's runbook or the next device session)

## Notes
- Research first: whether pfctl can add the `anchor "com.apple/*"` line to the running main ruleset without reloading it (it may need `-f` of the whole main ruleset as read back).
- From TP-048's review rounds 2 and 3 (R2.5, RR58).

## Log
- 2026-11-12 created in backlog (from TP-048's review)
