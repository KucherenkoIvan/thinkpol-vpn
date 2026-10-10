---
id: TP-022
title: "Local service API and CLI"
milestone: M1
area: cmd
repo: thinkpol-vpn
size: M
depends_on: [TP-011, KRN-001]
refs: [D8, DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
A running device node is controlled through a local API, and the CLI is its first client (the tray app is the second, in M5).

## Scope
- gRPC API on a root-owned Unix socket, group-accessible (`thinkpol` group): connect, disconnect, status (space, chain, entry, health), switch rule preset, list enrolled spaces.
- Contracts in-repo (buf); unary calls only (streaming status waits for KRN-002).
- CLI: `thinkpol connect | disconnect | status | rules preset <name>`.

## Acceptance
- [ ] the CLI controls a running device node in the lab
- [ ] a user outside the group gets permission denied

## Log
- 2026-10-10 created in backlog
