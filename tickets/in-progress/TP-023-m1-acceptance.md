---
id: TP-023
title: "M1 acceptance"
milestone: M1
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-013, TP-014, TP-017, TP-019, TP-020, TP-021, TP-022, TP-078, TP-079, TP-092]
refs: [DESIGN#milestones]
needs_human: macos
owner: glm-tp023
branch: tp-023-m1-acceptance
---

## Goal
M1's "done when" as lab tests, plus one real-world run on macOS.

## Scope
- Lab: browse the `internet` target through an egress node; `direct` vs tunneled destinations; DNS leak test; IPv6 leak test; overlay names; CLI connect/disconnect; teardown leaves nothing.
- The macOS checklists from TP-019 and TP-078 run once by the author on a real network.

## Acceptance
- [ ] lab tests green; they cover Linux leak guarantees (DNS, IPv6, the route table) and match DESIGN M1
- [ ] macOS checklist results recorded in Notes; M1's claim for macOS is exactly what the checklist shows (data plane TP-019, IPv6 guard TP-078), worded so nobody reads it as "macOS is safe" (independent design review, 2026-10-13)

## Notes
- **Scope of the leak guarantees (TP-062), superseded 2026-10-15:** M1 needs a real Mac; TP-019 and TP-078 are in `depends_on`. The Linux-only acceptance fallback no longer applies.
- **M1 claim (author, 2026-10-15):** M1 proves the core works on a real Mac and on Linux. It does not claim daily use. Daily use is success metric 2, and it starts after M2's disguised transport.

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): acceptance scoped: leak guarantees are Linux-only until TP-019/TP-021
- 2026-10-15 decision (author, 2026-10-15): M1 is working core, not daily use; daily use waits for M2 disguised transport
- 2026-10-15 docs (backlog grooming): depends on TP-019 and TP-078; macOS required for M1 acceptance; TP-079 when merged
- 2026-10-15 docs (backlog grooming, review fixes): Scope checklists TP-078; acceptance wording restored
- 2026-10-15 docs: depends on TP-079 (merged)
- 2026-10-16 docs (TP-078 device session A): depends on TP-092
- 2026-10-16 backlog → in-progress, owner glm-tp023, branch tp-023-m1-acceptance
