---
id: TP-118
title: "Decide: may -egress-allowed open the cloud metadata services?"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-112]
refs: [docs/design/server-agent.md#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
An exit's spaces can never reach a cloud metadata service unless the owner decided they may, and DESIGN says which.

## Scope
- Today `-egress-allowed` (`supervisor.Options.EgressAllowed`) may name any prefix: config accepts it, `EgressRefused` checks the allowed list first, and the root table jumps to accept before the blocked-range drops. So `-egress-allowed 100.64.0.0/10` (or `fd00:ec2::/64`, `169.254.0.0/16`, `168.63.129.16/32`) opens a metadata service's credentials to every space. DESIGN says EgressAllowed may name exceptions to the blocked ranges, metadata services included.
- Decide (owner): keep that, or keep the metadata hosts closed whatever EgressAllowed says (drop them before the allowed jumps, check them first in `EgressRefused`, refuse or warn on an overlapping prefix in config). TP-112 lists them for the refusal hint only.
- Implement the decision, update DESIGN, and test it in the supervisor's unit tests and the lab.

## Acceptance
- [ ] the decision is in DESIGN
- [ ] tests (unit and lab) show the metadata hosts' behaviour with an overlapping `-egress-allowed`
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-112's round-2 reviews (2026-10-21).

## Log
- 2026-10-21 created in backlog (TP-112 review round 2)
