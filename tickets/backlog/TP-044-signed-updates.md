---
id: TP-044
title: "Signed agent updates"
milestone: M4
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-037, TP-017]
refs: [A9]
owner: ""
branch: ""
---

## Goal
Nodes update themselves from signed releases distributed through the network (should-have).

## Scope
- Release signing key; signed release manifests distributed as blobs.
- Agent self-update with rollback if the new version fails to start.

## Acceptance
- [ ] a bad release rolls back automatically in the lab

## Log
- 2026-10-10 created in backlog
