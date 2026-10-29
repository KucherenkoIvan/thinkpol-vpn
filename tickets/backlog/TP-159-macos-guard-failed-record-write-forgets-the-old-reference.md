---
id: TP-159
title: "macOS guard: a failed record write in takeReference forgets the old reference"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-137]
refs: [RR11]
owner: ""
branch: ""
---

## Goal
A record write that fails after `pfctl -E` never loses the reference the guard held before, so the guard never leaves pf on after Close because of it.

## Scope
- `takeReference` (internal/dataplane/firewall/guard_darwin.go, TP-137's branch, ~789-792) sets `g.token` to the new reference, then returns the error if `recordToken` fails, before the `old != nil` branch that releases the reference held before. The old token is gone from the guard and the record now has neither.
- This only leaks if pf keeps a reference listed after `pfctl -d` (unverified on XNU). If it does, nothing ever releases the old reference, and pf stays on after Close. That contradicts doc.go's "a reference is never held unrecorded or forgotten".
- Fix it one of these ways and say which in Notes:
  - keep the old reference in a pending-release slot that later Applies and Close retry until pf no longer lists it (`release` already treats "not listed" as done);
  - release the old reference before returning the write error.
- The package doc's "enabling pf by reference" section says what happens to the old reference when the record write fails.

## Out of scope
- Whether XNU keeps references listed after `pfctl -d`: a device check, not this ticket.
- pf off with an unreadable References listing: TP-160. A vanished reference while pf is on: TP-161.

## Acceptance
- [ ] a unit test with the fake pfctl: the guard holds a reference that pf still lists, pf is found off, `-E` succeeds and the record write fails; after a later Apply that succeeds, and after Close, pf lists neither reference. Mutation: returning before the old reference is kept or released fails it
- [ ] doc.go's "never held unrecorded or forgotten" holds for this path, and the doc says how
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-137 round-1 reviews and implementer, 2026-10-29.
- Read the code with `git show origin/tp-137-macos-guard-kills-states-without-a-token:internal/dataplane/firewall/guard_darwin.go` until TP-137 merges.

## Log
- 2026-10-29 created in backlog (TP-137 round-1 review)
