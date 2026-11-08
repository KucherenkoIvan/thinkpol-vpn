---
id: TP-085
title: "macOS DNS-leak capture (PRD R4)"
milestone: M2
area: dataplane/path
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-019]
split_from: TP-080
refs: [R4, D6, docs/design/milestones.md#milestones, docs/design/overlay.md#data-plane-every-node-one-binary]
needs_human: macos
owner: ""
branch: ""
---

## Goal
The macOS DNS-leak evidence PRD R4 asks for (docs/design/milestones.md M1): a capture of the physical interface shows a direct name's query and not a tunnel-bound name's.

## Scope
- A device run, recorded not judged: capture the physical interface, resolve one direct name and one tunnel-bound name, and keep both names with the capture.

## Out of scope
- Redialing at once on a network change, and the Wi-Fi-change captures: TP-179 (after the MVP).

## Acceptance
- [ ] device, recorded not judged (ORCHESTRATION.md "Device testing (2026-10-16)"): while the physical interface is captured, resolve one direct name and one tunnel-bound name and write both names down with the capture. An agent judges the evidence after the run

## Notes
- Split from TP-080 (backlog grooming 2026-10-15).
- Carries R4's macOS DNS-leak evidence (PRD R4, docs/design/milestones.md M1): the agent checks afterwards that the direct name's query appears in the physical-interface capture (proving the capture saw DNS) and the tunnel-bound name's does not.
- Split 2026-11-07 (owner's MVP cut): the redial-without-the-6 s-wait work, its device checks and the carried-over TP-019 Wi-Fi-change items moved to TP-179.

## Log
- 2026-10-15 created in backlog (split from TP-080, backlog grooming)
- 2026-10-15 docs (backlog grooming, review fixes): DESIGN ref slug
- 2026-10-16 docs (TP-023 round 2): the device acceptance carries TP-019's leftover step 8 captures and step 15b (both during a Wi-Fi change), in the record-don't-judge form
- 2026-10-16 docs (TP-023 round 3): refs R4 and D6 added; the carried-over TP-019 items moved from Acceptance to Notes
- 2026-10-18 docs (TP-099): acceptance gained the DNS-leak capture with a positive control
- 2026-10-19 docs (TP-099 round 4): the DNS-leak box recorded, not judged; Notes carry R4's macOS capture
- 2026-10-19 docs (TP-099 rounds 3–5): the DNS-leak box records; Notes say what the agent checks
- 2026-11-07 split (owner's MVP cut): only R4's DNS-leak capture stays; redial → TP-179
