---
id: TP-207
title: "Kill switch from boot, before the agent starts"
milestone: M3
area: agent
stream: core
repo: thinkpol-vpn
size: M
depends_on: [TP-048, TP-046]
refs: [D4, RR59]
needs_human: macos
owner: ""
branch: ""
---

## Goal
With the kill switch on (or the crash posture meant up for this boot), nothing leaves the device between power-on and the agent's first apply. Neither the nftables table nor the pf anchor survives a reboot today (RR59).

## Scope
- Linux: a oneshot unit, ordered before network-pre.target, that applies the down shape from the stored settings and the last map's entries, without the agent.
- macOS: a boot-time pf rule set that holds the same until the agent takes over (a launchd job early in boot, or what pf.conf can carry), released by the agent's first apply.
- The service install and uninstall put it in and take it out (TP-046's definitions).
- docs: security.md, RR59, the service package doc.

## Out of scope
- Changing what the down shape lets out.

## Acceptance
- [ ] Linux: under systemd in the lab, a reboot-like start (the oneshot alone, the agent held off) leaves the down shape in place before the network is up (lab test, mutation-checked)
- [ ] the agent's first apply takes the boot shape over with no moment without rules (lab test)
- [ ] `thinkpol service uninstall` removes the oneshot and its rules (lab test)
- [ ] macOS: the boot rule as installed (unit test); device check row: reboot with the kill switch on, nothing leaves before the agent connects

## Notes
- The oneshot must not need the network or the controller: entries come from the last map on disk.
- From TP-048's review (R1.5, RR59).

## Log
- 2026-11-12 created in backlog (from TP-048's review)
