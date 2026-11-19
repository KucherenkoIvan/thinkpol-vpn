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
- How slots are handed out now: lab/hostlock.go (acquireSlotLock and the slot queue's doc comment) and lab/README.md, "A cap on labs". In short: each waiter takes a numbered ticket in the lock directory's `slot-queue/`, a file it holds flock'd while it waits (numbers assigned under `slot-queue.lock`); only the oldest waiter tries the slot locks (every 100 ms), each other waiter checks only the ticket just ahead of its own (one non-blocking flock and one fstat per 100 ms) and looks again when that one leaves.
- Dead and stuck waiters: a killed waiter's flock goes with its process, and a ticket nobody holds locked is removed by the next scan that meets it; a waiter whose wait ends removes its own ticket. A ticket that is locked but not refreshed for 15 s (heartbeat every 1 s: a stopped process, a leaked lock) is passed over but left in place.
- Degrading safely: entries in `slot-queue/` that aren't tickets (other names, directories, files that can't be opened) are ignored; a queue that can't be used at all (`slot-queue` isn't a directory, a ticket can't be created, the sequence would overflow) makes the waiter fall back to polling the slots in no order, as before. So nothing in the queue can keep a free slot from being taken. TP-242's bounds and messages are unchanged (`no lab slot within …`, `lab: waiting for a free lab slot (THINKPOL_LAB_MAX_LABS): …`), and so are TP-254's timeline lines. A wait with no time left still takes a free slot if no live waiter is ahead of it.
- Until this is merged, runs from rewrite still poll the slots directly and ignore the queue: on a shared host they compete with queued waiters in no order.
- Measurement: two concurrent full `make lab-test` runs per side, each with its own `THINKPOL_LAB_TIMELINE`, slot waits from the timeline's `slot-wait` lines. Before = rewrite 877b3931, after = 38175ccf (this branch with that rewrite merged). Other runs' labs shared the host and its slots in both cases.

  | pair | node phase | lab starts per run | slot wait median | p90 | max | wall |
  |---|---|---|---|---|---|---|
  | before, 1 | 40 packages run | 97 | 182 s / 177 s | 694 s / 843 s | 1596 s / 1780 s | 2388 s / 2551 s |
  | after, 1 | 40 packages run, harness phase too (its hash changed) | 111 | 413 s / 416 s | 951 s / 958 s | 1138 s / 1171 s | 3166 s / 3422 s |
  | before, 2 | 40 of 40 cached | 57 | 104 s / 214 s | 446 s / 506 s | 1428 s / 1095 s | 2102 s / 2287 s |
  | after, 2 | 40 of 40 cached | 57 | 245 s / 265 s | 322 s / 338 s | 382 s / 352 s | 2135 s / 2282 s |

  The second pairs are the like-for-like comparison (the same 57 lab starts per run, nothing else in the default stream): the longest slot wait drops from 1428 s and 1095 s to 382 s and 352 s, about 3 to 4 times less, while the median rises (104 s and 214 s to 245 s and 265 s) and the mean stays about where it was (193 s and 257 s before, 221 s and 257 s after). First come, first served doesn't add slots, so it doesn't shorten a run (wall times unchanged); it takes the long tail off, which is what TP-242's deadline cut punishes. The first after-pair isn't comparable with the first before-pair: it also ran the harness phase (14 more lab starts, the harness taking 1255 s and 1535 s) and took longer, and 7 of after-1a's slot waits began after the test binary's deadline less TP-242's reserve, so they failed with `no lab slot within 0s, cut short by the test's deadline` (TP-242's documented price, not the queue: the run was 52m45s).
- Full lab runs: all six full runs' tests passed except after-1a's 7 deadline-cut lab starts above; every run was over the 15-minute budget with the other runs beside it.

## Log
- 2026-11-19 created in backlog (TP-254 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-260
- 2026-11-19 slot queue in lab/hostlock.go (tickets flock'd in slot-queue/, head-only slot polling, dead tickets removed, stale ones skipped, fallback to unordered polling); tests in lab/hostlock_test.go across goroutines and child processes; lab/README.md and lab.go's comment updated
- 2026-11-19 mutations, each failing its test: every waiter at the head (TestSlotsGoInArrivalOrder, TestNewcomerWaitsBehindLiveWaiter); a dead ticket ahead counted as live (TestKilledWaiterLeavesNoGap, by its bound below the 15 s staleness); a waiter that gives up keeps its ticket file (TestWaiterPastDeadlineLeavesQueue); stale tickets not skipped (TestStuckWaiterIsSkipped); no fallback on an unusable queue (TestBrokenQueueDoesNotBlockSlots); a new ticket numbered the same as the last live one (TestNewcomerWaitsBehindLiveWaiter); scans keep dead tickets (TestDeadTicketIsRemoved, TestKilledWaiterLeavesNoGap)
- 2026-11-19 runs: the new tests -race -count=10 green; lab-gotest PKG=./lab of them COUNT=3 green in a lab node; make lint green at 4bd243ee, make test green at 38175ccf; two full-lab pairs before (877b3931) and after (38175ccf), numbers in Notes
