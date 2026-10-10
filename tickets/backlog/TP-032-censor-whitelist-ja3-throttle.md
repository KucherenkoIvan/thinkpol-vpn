---
id: TP-032
title: "Censor modules: whitelist, TLS fingerprints, throttling"
milestone: M3
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024]
refs: [C4]
owner: ""
branch: ""
---

## Goal
The lab reproduces whitelist mode, TLS fingerprint filtering and volume throttling.

## Scope
- Whitelist mode: only allow-listed destination IPs and SNIs pass.
- JA3/JA4 computation with an allow-list of common browser fingerprints.
- Volume throttling: flows to non-domestic addresses slowed or frozen after N kilobytes.

## Acceptance
- [ ] Go's default `crypto/tls` client is blocked by the JA3/JA4 allow-list while the uTLS Chrome fingerprint passes
- [ ] whitelist mode blocks everything not listed

## Log
- 2026-10-10 created in backlog
