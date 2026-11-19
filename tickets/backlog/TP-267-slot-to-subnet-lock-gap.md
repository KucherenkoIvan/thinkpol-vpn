---
id: TP-267
title: "A lab waits ~25 s between getting its slot and asking for the subnet lock"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
In two of TP-263's runs (2026-11-19), 25–26 s passed between a lab getting its slot and asking for the subnet lock (`THINKPOL_LAB_TIMELINE`: routetable after the change, packettest before). Every lab start pays that gap while holding a slot other labs wait for.

## Scope
- Find what runs in that gap (image build check, binary prepare, compose file render, docker info).
- Remove it, or move it before the slot is taken.

## Acceptance
- [ ] The gap explained with a timeline.
- [ ] The gap under 2 s, or why it can't be.

## Notes

## Log
- 2026-11-19 created in backlog (TP-263)
