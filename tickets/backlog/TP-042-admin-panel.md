---
id: TP-042
title: "Admin panel and dashboards"
milestone: M4
area: features/webui
repo: thinkpol-vpn
size: L
depends_on: [TP-035, TP-041]
refs: [A6, A8]
owner: ""
branch: ""
---

## Goal
The space is managed from a web panel reachable only through the overlay.

## Scope
- `webui` pages: spaces, members, nodes (ingress/egress toggles), chains, rules, invites, grants.
- Dashboards: node health, connected devices, traffic rates, transports in use, active routes, failures per transport and entry.

## Acceptance
- [ ] everything the admin CLI can do is possible from the panel
- [ ] the panel isn't reachable on a public address

## Log
- 2026-10-10 created in backlog
