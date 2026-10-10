---
id: TP-023
title: "M1 acceptance"
milestone: M1
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-013, TP-014, TP-017, TP-020, TP-021, TP-022]
refs: [DESIGN#milestones]
owner: ""
branch: ""
---

## Goal
M1's "done when" as lab tests, plus one real-world run on macOS.

## Scope
- Lab: browse the `internet` target through an egress node; `direct` vs tunneled destinations; DNS leak test; IPv6 leak test; overlay names; CLI connect/disconnect; teardown leaves nothing.
- The macOS checklists from TP-019 and TP-021 run once by the author on a real network.

## Acceptance
- [ ] lab tests green
- [ ] macOS checklist results recorded in Notes

## Log
- 2026-10-10 created in backlog
