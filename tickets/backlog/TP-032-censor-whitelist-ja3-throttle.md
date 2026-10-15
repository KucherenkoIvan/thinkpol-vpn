---
id: TP-032
title: "Censor modules: whitelist, TLS fingerprints, throttling"
milestone: M3
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024, TP-064]
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
- Server hello fingerprints (JA3S/JA4S): TP-026; this module consumes them for whitelist mode and the matrix.

## Acceptance
- [ ] Go's default `crypto/tls` client is blocked by the JA3/JA4 allow-list while the uTLS Chrome fingerprint passes
- [ ] whitelist mode blocks everything not listed
- [ ] with TP-026's server fingerprints, the matrix compares a node's server hello to the camouflage site's

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): JA3S/JA4S for the response side
- 2026-10-15 docs (backlog grooming): server JA3S/JA4S owned by TP-026
