---
id: TP-032
title: "Censor modules: whitelist, TLS fingerprints, throttling"
milestone: M3
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024, TP-026, TP-064, TP-089]
refs: [C4]
owner: ""
branch: ""
---

## Goal
The lab reproduces whitelist mode, TLS fingerprint filtering and volume throttling.

## Scope
- Whitelist mode, as docs/design/lab.md describes it: drop everything whose destination address isn't listed, then check the handshake's name (SNI) on what's left; drop UDP even to listed addresses; variants that throttle the rest to about 14 kb/s, reset it, or let it time out. A name-only check (address not checked) is a separate, weaker module.
- JA3/JA4 computation with an allow-list of common browser fingerprints.
- Volume throttling: flows to non-domestic addresses slowed or frozen after N kilobytes.
- Server hello fingerprints (JA3S/JA4S): TP-026; this module consumes them for the matrix.

## Acceptance
- [ ] Go's default `crypto/tls` client is blocked by the JA3/JA4 allow-list while the uTLS Chrome fingerprint passes
- [ ] whitelist mode drops a disguised handshake carrying a listed name to an unlisted address
- [ ] UDP to a listed address is dropped; TCP to it passes
- [ ] each variant (drop, throttle, reset, time out) has a matrix column, and so does the name-only module
- [ ] with TP-026's server fingerprints, the matrix compares a node's server hello to the camouflage site's

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): JA3S/JA4S for the response side
- 2026-10-15 docs (backlog grooming): server JA3S/JA4S owned by TP-026
- 2026-10-15 docs (backlog grooming, review fixes): depends_on TP-026; whitelist-mode wording dropped from JA3S line
- 2026-10-15 depends_on TP-089 (split from TP-024 review)
- 2026-10-16 docs: whitelist mode per the 2026 research (address first, then the name; UDP dropped to listed addresses; variants; name-only as a separate module)
