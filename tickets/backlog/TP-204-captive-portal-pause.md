---
id: TP-204
title: "Captive-portal pause for the kill switch"
milestone: M2
area: dataplane/firewall
stream: core
repo: thinkpol-vpn
size: M
depends_on: [TP-048]
refs: [D4, RR17]
needs_human: macos
owner: ""
branch: ""
---

## Goal
A member on a captive-portal network (hotel or airport Wi-Fi) can briefly let the OS reach the portal while the kill switch holds, without turning the kill switch off. The pause ends by itself, and status shows it while it runs. Owner decision 2026-11-09: its own ticket, in M2, before the gate (TP-029).

## Scope
- An explicit, time-limited pause command (`thinkpol kill-switch pause`, local API and status), refused while connected; it ends by itself after a bounded time, on connect, or on `kill-switch on` again.
- What the pause lets through: either the portal's DNS and HTTP(S) only, or a short direct window. Open design question: settle it with the orchestrator before building (see Notes).
- Status and health show the pause and its remaining time; the agent logs its start and end.
- docs: security.md (the kill switch section), RR17 narrowed, the firewall and agent package docs.

## Out of scope
- Detecting a portal automatically (probing captive.apple.com or similar): later, if wanted.
- Windows (TP-076).
- The tray's button (TP-049/M5); this ticket gives it the local API call.

## Acceptance
- [ ] Linux: with the kill switch on and down, a pause lets the chosen traffic out and nothing else; it ends by itself and the down shape is back (lab test in the firewall or agent package, mutation-checked)
- [ ] the pause can't outlive its bound: an agent crash or stop during a pause leaves the down shape, not the pause (lab test, mutation-checked)
- [ ] status and health show the pause and its end (unit test on the local API and the status render)
- [ ] macOS: the pause as pf loads it (unit test with the fake pfctl); a device check row in TP-029's runbook: log in to a real captive portal with the kill switch on

## Notes
- Open design question for the implementer and the orchestrator: (a) portal-only: DNS to the LAN's resolver plus HTTP(S) to the addresses it answers, narrow but brittle (portals redirect across hosts, some use HTTPS on IPs the lookup didn't name); (b) a short direct window (say 60 s, everything direct), simple and robust but a real leak window. Decide before any code; record the choice and why here and in security.md.
- R2.8/RR62: the down shape refuses DNS to the LAN even with allow-LAN; the pause must deliberately let the portal's lookup through.
- The pause must not be stored as a toggle: a restart without the agent's memory of it falls back to the down shape.

## Log
- 2026-11-12 created in backlog (from TP-048's review; owner decision 2026-11-09)
