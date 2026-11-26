---
id: TP-287
title: "The default stream takes free lab slots first"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-287"
branch: "tp-287-default-stream-slots-first"
---

## Goal
A full `make lab-test` stays within the default stream's 15-minute budget while long-stream lab tests run beside it. Lab slots go first come, first served across runs (TP-260's ticket queue in the lock directory, lab/hostlock.go), so a long-stream lab that queued earlier takes a freed slot ahead of a default-stream lab that waits, and the default stream, the one under the budget, loses minutes. Measured on tp-080-path-liveness (2026-11-23, which adds long-stream lab tests holding up to 7 labs for minutes): with the long stream capped at 3 parallel tests (`LAB_LONG_PARALLEL ?= 3`) the default stream took 15m24s (24 s over, exit 3), the long stream 13m55s, total 15m24s; at cap 2, default 15m10s and total 21m44s. The censor matrix waits up to ~3 min at the start for a free slot. rewrite alone runs the default stream in ~12m26s. Every lab test already knows its stream: `THINKPOL_LAB_STREAM` is `default` or `long` under `make lab-test` (lab/README.md, "Streams"). Give the default stream first pick of a freed slot.

## Scope
- A freed slot goes to the oldest waiter of the default stream when one is waiting, else to the oldest waiter of any kind; a waiter outside a stream counts as default.
- A waiter's class comes from `THINKPOL_LAB_STREAM` and is recorded in its queue entry, so other runs' waiters see it.
- Order within a class stays first come, first served across runs.
- A dead waiter still leaves the queue without blocking anyone or leaking a slot: TP-260's guarantees keep holding.
- lab/README.md and lab/hostlock.go's docs say how slots are handed out.

## Out of scope
- The slot cap (`THINKPOL_LAB_MAX_LABS`), `LAB_LONG_PARALLEL`, test bodies.

## Acceptance
- [ ] (a) A long-stream waiter that queued earlier does not take a freed slot while a default-stream waiter waits. Test with concurrent waiters; mutation: plain FIFO → the test fails.
- [ ] (b) Within one class, arrival order holds, and a long-stream waiter still gets a slot when no default waiter is left (test).
- [ ] (c) A dead waiter of either class leaks no slot and blocks no one (the existing tests still pass, extended to both classes).
- [ ] (d) Measured: one full `make lab-test` of tp-080-path-liveness with this branch merged in: its default, long and total times, its exit, and the censor matrix's first slot wait, against the 3-parallel run above.
- [ ] (e) Measured: one full `make lab-test` of this branch alone (rewrite and the fix): default and total times, so rewrite isn't slower.
- [ ] (f) lab/README.md and lab/hostlock.go's docs say how slots are handed out.

## Notes
- TP-260 (done) built the queue this changes: tickets in the lock directory's `slot-queue/`, flock'd by their waiters, numbered in arrival order.

## Log
- 2026-11-26 created in backlog (lab speed: tp-080-path-liveness over budget)
- 2026-11-26 backlog → in-progress, owner: agent-tp-287
