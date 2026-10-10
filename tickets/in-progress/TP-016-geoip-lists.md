---
id: TP-016
title: "GeoIP lists"
milestone: M1
area: lists
repo: thinkpol-vpn
size: M
depends_on: [TP-003]
refs: [R9]
owner: agent-tp-016
branch: tp-016-geoip-lists
---

## Goal
Country prefix lists in a compact, content-addressed form the map can reference.

## Scope
- Importers for v2fly `geoip.dat` and DB-IP Lite CSV into normalized per-country prefix sets.
- CIDR aggregation (merge adjacent and overlapping prefixes) with size stats.
- Content-addressed blob format (sha256 of canonical bytes) referenced from the map header.
- `thinkpol dev lists build`.
- Code lives in `internal/lists` (outside `dataplane`, since the controller builds lists too); distribution is TP-017's `dataplane/blobs`.

## Acceptance
- [ ] building the same input twice gives the same hash
- [ ] aggregation stats for the RU list recorded in Notes (prefix count before/after)

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-016, branch: tp-016-geoip-lists
