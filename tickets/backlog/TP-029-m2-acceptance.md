---
id: TP-029
title: "M2 acceptance"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-025, TP-026, TP-087, TP-188]
refs: [C1, C2, C4]
owner: ""
branch: ""
---

## Goal
M2's "done when": the matrix shows `udp` getting caught and `reality` passing.

## Scope
- Run the full matrix; `reality` passes every M2 module; `udp`'s failures recorded (expected: the fully-encrypted heuristics).

## Acceptance
- [ ] `lab/RESULTS.md` committed with the M2 matrix
- [ ] the wireguard-rhythm cell's probe runs for at least two WireGuard rekey periods (up to about 7 minutes; up to about 10 minutes when the transport batches records; see lab/censor/doc.go) with the transport's default settings, so a pass means the rhythm was looked for (a ~30 s probe passes trivially)

## Notes
- What "`reality` passes" means (owner, 2026-11-07): the handshake-level checks (blocklists, VPN fingerprints, entropy, the active prober, the server-hello fingerprint) and no WireGuard rhythm (TP-188). Flow shape beyond that is not tested at M2. See docs/design/milestones.md.
- The wireguard-rhythm cell's probe runs for at least two WireGuard rekey periods (≥ 5 minutes) with the transport's default settings, so a pass means the rhythm was looked for (a ~30 s probe passes trivially)

## Log
- 2026-10-10 created in backlog
- 2026-10-15 deps (board op): TP-028 → TP-087, `reality` is the M2 disguised transport
- 2026-10-15 docs (board op): Goal and Scope say `reality` instead of `tls`
- 2026-11-07 notes and deps: the M2 gate's meaning (owner, 2026-11-07); depends on TP-188 (WireGuard-rhythm check)
- 2026-11-07 rhythm-cell probe length added (from TP-188's reviews)
- 2026-11-07 rhythm probe length corrected after TP-188 merged
