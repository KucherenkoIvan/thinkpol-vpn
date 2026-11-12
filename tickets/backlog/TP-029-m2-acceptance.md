---
id: TP-029
title: "M2 acceptance"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-025, TP-026, TP-087, TP-188, TP-201]
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
- The wireguard-rhythm cell's probe runs for at least two WireGuard rekey periods (up to about 7 minutes; up to about 10 minutes when the transport batches records; see lab/censor/doc.go) with the transport's default settings, so a pass means the rhythm was looked for (a ~30 s probe passes trivially)
- Owner, 2026-11-08: the Mac device session runs as part of this acceptance run, one runbook: reality on the Mac, TP-085's DNS-leak capture, the macOS kill switch if TP-048 has merged, and TP-144's checklist (owner, 2026-11-09: all device-test work runs in this session).

## Log
- 2026-10-10 created in backlog
- 2026-10-15 deps (board op): TP-028 → TP-087, `reality` is the M2 disguised transport
- 2026-10-15 docs (board op): Goal and Scope say `reality` instead of `tls`
- 2026-11-07 notes and deps: the M2 gate's meaning (owner, 2026-11-07); depends on TP-188 (WireGuard-rhythm check)
- 2026-11-07 rhythm-cell probe length added (from TP-188's reviews)
- 2026-11-07 rhythm probe length corrected after TP-188 merged
- 2026-11-07 Notes probe length aligned with its acceptance box
- 2026-11-08 deps: TP-201 (reality behind the shared listener and in the matrix, split from TP-087). Owner, 2026-11-08: the Mac device session runs as part of this acceptance run, one runbook: reality on the Mac, TP-085's DNS-leak capture, the macOS kill switch if TP-048 has merged, and TP-144's checklist unless it ran earlier (timing open with the owner).
- 2026-11-09 notes: all device-test work in the acceptance session (owner)
- 2026-11-12 depends on TP-204 (captive-portal pause, owner 2026-11-09)
- 2026-11-12 depends_on: TP-204 removed (dropped, owner 2026-11-12)
