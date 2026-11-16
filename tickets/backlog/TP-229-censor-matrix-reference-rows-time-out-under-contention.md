---
id: TP-229
title: "Censor-matrix reference rows time out on lab setup under contention"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
A full `make lab-test` fails on censor-matrix reference cells (e.g. `TestCensorMatrix/relay-tcp_(reference)/server-hello`, `openvpn-tcp (reference)`) when other labs run on the same host: `docker compose up` is still creating containers at the 600 s limit (one hung with 3 of 7 containers started), or cells wait on the lab's subnet allocation lock. Seen in three branches' full labs on 2026-11-16, each on a loaded host (load ~11 on 6 cores). M2 closes on a green full lab, so this must be fixed or bounded.

## Scope
- Find why compose up stalls (image pulls, network creation, the subnet lock's hold time, container start under CPU pressure), with evidence.
- Make the matrix robust (bounded and honest waits, setup that doesn't hold a shared lock longer than needed, or serialising matrix setup) without hiding a real failure.

## Out of scope

## Acceptance
- [ ] The cause named in Notes with evidence from a run under load.
- [ ] Three consecutive full `make lab-test` runs under the same kind of load pass the matrix's reference rows, or fail only with a message naming the real cause.
- [ ] No retry that would hide a genuine setup failure; any timeout change has a stated reason.

## Notes

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
