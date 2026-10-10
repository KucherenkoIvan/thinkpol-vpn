---
id: TP-004
title: "Dev tooling for hand-made maps"
milestone: M0
area: cmd
repo: thinkpol-vpn
size: M
depends_on: [TP-003]
refs: [DESIGN#joining]
owner: ""
branch: ""
---

## Goal
Until the controller exists (M4), maps made by hand from a YAML spec drive the lab and early real use.

## Scope
- `thinkpol dev keygen`: space signing and recovery keys, node keys; private key files written `0600`.
- `thinkpol dev map build spec.yaml --out map.bin`: assigns overlay IPv4 from `100.64.0.0/10` and IPv6 from a random ULA /48 unless fixed in the spec, builds and seals each node's section, pads, signs.
- `thinkpol dev map inspect map.bin [--node-key k]`: verifies and prints the header; with a node key, prints that node's section.
- Spec format documented (in `lab/README.md` or command help) with an example used by the lab.

## Out of scope
The admin CLI and controller (TP-034 decides whether these commands stay).

## Acceptance
- [ ] the lab generates its maps with these commands
- [ ] `inspect` reports a tampered map as invalid
- [ ] the commands are clearly labelled as development tooling

## Log
- 2026-10-10 created in backlog
