---
id: TP-041
title: "Telemetry"
milestone: M4
area: features/telemetry
repo: thinkpol-vpn
size: L
depends_on: [TP-034, TP-011]
refs: [S2, S3, S4, A8]
owner: ""
branch: ""
---

## Goal
Admins see what's happening without nodes holding anything useful to a censor.

## Scope
- Node side: per-space in-memory ring; each record sealed to the space's telemetry key when written; bounded (minutes, tens of KB); aggregates per link and device id only, never public IPs or destinations.
- Agent logs in an in-memory ring, readable over the overlay (S2).
- Shipping when the controller is reachable; controller ingest with 24 h retention.
- Node owners see per-space volume on their nodes; guests see only their slice.

## Acceptance
- [ ] a node's memory dump contains no readable telemetry (checked in TP-045)
- [ ] telemetry survives a short controller outage within the buffer bound

## Log
- 2026-10-10 created in backlog
