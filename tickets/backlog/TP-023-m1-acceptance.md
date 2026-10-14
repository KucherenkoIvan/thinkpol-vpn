---
id: TP-023
title: "M1 acceptance"
milestone: M1
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-013, TP-014, TP-017, TP-020, TP-021, TP-022]
refs: [DESIGN#milestones]
needs_human: macos
owner: ""
branch: ""
---

## Goal
M1's "done when" as lab tests, plus one real-world run on macOS.

## Scope
- Lab: browse the `internet` target through an egress node; `direct` vs tunneled destinations; DNS leak test; IPv6 leak test; overlay names; CLI connect/disconnect; teardown leaves nothing.
- The macOS checklists from TP-019 and TP-021 run once by the author on a real network.

## Acceptance
- [ ] lab tests green. They cover **Linux only**: M1's leak guarantees (DNS, IPv6, the route table) are Linux-only until TP-019 and TP-021 land, and the lab says nothing about macOS
- [ ] macOS checklist results recorded in Notes; M1's claim for macOS is exactly what the checklist shows, and the acceptance is worded so nobody reads it as "macOS is safe" (independent design review, 2026-10-13)

## Notes
- **Scope of the leak guarantees (TP-062):** TP-019 is not in `depends_on`. If it isn't done when this runs, M1 is accepted as Linux-only and Notes say so.
- **M1 claim (author, 2026-10-15):** M1 proves the core works on a real Mac and on Linux. It does not claim daily use. Daily use is success metric 2, and it starts after M2's disguised transport.

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): acceptance scoped: leak guarantees are Linux-only until TP-019/TP-021
- 2026-10-15 decision (author, 2026-10-15): M1 is working core, not daily use; daily use waits for M2 disguised transport
