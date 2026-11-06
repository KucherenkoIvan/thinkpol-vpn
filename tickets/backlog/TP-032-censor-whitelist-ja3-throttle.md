---
id: TP-032
title: "Censor modules: TLS fingerprints, throttling"
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
The lab reproduces TLS fingerprint filtering and volume throttling.

## Scope
- JA3/JA4 computation with an allow-list of common browser fingerprints.
- Volume throttling: flows to non-domestic addresses slowed or frozen after N kilobytes.
- Server hello fingerprints (JA3S/JA4S): TP-026; this module consumes them for the matrix.

## Out of scope
- Whitelist mode and the UDP-to-listed-address drop: TP-177 (after the MVP).

## Acceptance
- [ ] Go's default `crypto/tls` client is blocked by the JA3/JA4 allow-list while the uTLS Chrome fingerprint passes
- [ ] a flow to a non-domestic address is slowed or frozen after N kilobytes, and the matrix has a column for it
- [ ] with TP-026's server fingerprints, the matrix compares a node's server hello to the camouflage site's

## Notes
- Split 2026-11-07 (owner's MVP cut): whitelist mode and the UDP-to-listed-address drop moved to TP-177 (the owner deferred whitelist mode: research is ongoing). The throttling box is new: the scope had no box of its own.

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): JA3S/JA4S for the response side
- 2026-10-15 docs (backlog grooming): server JA3S/JA4S owned by TP-026
- 2026-10-15 docs (backlog grooming, review fixes): depends_on TP-026; whitelist-mode wording dropped from JA3S line
- 2026-10-15 depends_on TP-089 (split from TP-024 review)
- 2026-10-16 docs: whitelist mode per the 2026 research (address first, then the name; UDP dropped to listed addresses; variants; name-only as a separate module)
- 2026-11-07 split (owner's MVP cut): whitelist mode → TP-177; a throttling acceptance box added
