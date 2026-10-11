---
id: TP-012
title: "M0 acceptance in the lab"
milestone: M0
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-002, TP-011]
refs: [C1, DESIGN#milestones]
owner: "agent-tp-012"
branch: "tp-012-m0-acceptance"
---

## Goal
M0's "done when" as automated lab tests.

## Scope
- `device-a` ↔ `server-1` ping over overlay IPv4 and IPv6.
- `device-a` ↔ `device-b` through `server-1` as relay, IPv4 and IPv6.
- Capture at the router contains no WireGuard message signatures (type byte 1–4 followed by three zero bytes, 148/92-byte handshakes).

## Acceptance
- [ ] `make lab-test` is green with these tests

## Log
- 2026-10-10 created in backlog
- 2026-10-11 backlog → in-progress — owner: agent-tp-012, branch: tp-012-m0-acceptance (based on tp-011-thinkpol-up while TP-011 is in review)
