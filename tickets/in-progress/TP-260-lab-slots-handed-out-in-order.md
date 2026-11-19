---
id: TP-260
title: "Lab slots are handed out in order"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-260"
branch: "tp-260-fair-lab-slots"
---

## Goal
Lab slots are taken by polling, not in order (lab/hostlock.go: every waiter tries the slot locks every 250 ms and takes the first free one). With TP-254 a full lab has up to ~72 waiters (6 phases or processes × 12) polling for 12 slots, so a run with many waiting labs takes most of the slots that free up and other runs' labs wait far longer: TP-254's run 1 had a slot wait of 18m49s. Under TP-242's budget a wait that starts late fails with "no lab slot within 0s". Hand slots out first come, first served (a ticket queue in the lock directory), fair across runs.

## Scope
- Slot waiters queue in arrival order in the lock directory, and a freed slot goes to the oldest waiter, whichever run it belongs to.
- A waiter that dies (killed, its process gone) leaves the queue without holding up the ones behind it, and leaks no slot.
- lab/README.md and lab/hostlock.go's docs say how slots are handed out.

## Out of scope
- The slot cap itself (`THINKPOL_LAB_MAX_LABS`, its default) and how many labs a run asks for at once (TP-254).

## Acceptance
- [ ] Slots go to waiters in arrival order (test with concurrent waiters).
- [ ] Two concurrent full labs: max slot wait before/after in Notes.
- [ ] No slot leaks when a waiter dies (test).

## Notes

## Log
- 2026-11-19 created in backlog (TP-254 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-260
