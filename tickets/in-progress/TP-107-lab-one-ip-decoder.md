---
id: TP-107
title: "lab: one IP decoder"
milestone: M3
area: lab
repo: thinkpol-vpn
size: S
depends_on: []
owner: "agent-glm"
branch: "tp-107-lab-one-ip-decoder"
---

## Goal
Lab packet parsing shares one IP decoder instead of two parallel implementations.

## Scope
- Unify `lab/pcap.go` `decodeIP` (~152) and `lab/censor/packet.go` `decodePacket` (~66) into a single helper both call.
- Optionally reduce duplicated process-wide registries with separate mutexes where the merge is straightforward.

## Out of scope
- Changing censor verdict semantics or matrix scoring.
- Lab topology or harness redesign.

## Acceptance
- [ ] lab and censor tests that decode packets pass unchanged or note why they changed
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-107-lab-one-ip-decoder
