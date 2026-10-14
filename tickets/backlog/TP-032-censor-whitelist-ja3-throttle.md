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
- JA3S/JA4S computation for the response side, with the camouflage site's fingerprint as the reference, so the prober (TP-026) and the matrix can compare a node's server hello with the real site's (independent design review, 2026-10-13).

## Acceptance
- [ ] Go's default `crypto/tls` client is blocked by the JA3/JA4 allow-list while the uTLS Chrome fingerprint passes
- [ ] whitelist mode blocks everything not listed
- [ ] the lab computes JA3S/JA4S of a server hello and tells Go's default `crypto/tls` server from the camouflage site's

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): JA3S/JA4S for the response side
