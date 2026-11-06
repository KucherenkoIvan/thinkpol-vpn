---
id: TP-173
title: "Tests wait on sync points, not fixed sleeps, and assert state"
milestone: later
area: tests
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
Tests stop guessing how long something takes. A fixed `time.Sleep` makes a test slow when the guess is long and flaky when it is short; a count of calls tests the sequence, not the behaviour (AGENTS.md, "Tests").

## Scope
- Replace the fixed `time.Sleep` waits in `_test.go` files (97 of them, in 39 files, at filing) with sync points (a channel, an event the code already emits) or polling with a deadline.
- Start with `internal/dataplane/interface_test.go:195-200`: it sleeps 500 ms for "the router has seen it" and 1 s for "five retries' worth", then counts calls.
- Replace count-of-calls assertions (`calledAtLeast`, `len(ifc.calls())`) with assertions on the state the calls produce, where the state is observable.
- Sleeps that are the behaviour under test (a backoff measured against a fake clock, a real timeout) stay, each with a comment saying why.

## Out of scope
- Production code changes beyond adding a hook a test needs to wait on, kept unexported.

## Acceptance
- [ ] `grep -rn 'time.Sleep(' --include='*_test.go'` lists only the sleeps kept, each with its comment
- [ ] `make test` run 20 times in a row (`go test -count=20` on the changed packages) passes
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: a code-quality pass on 2026-11-07, recorded at the TP-139 owner session, 2026-11-07.
- Count checked at filing: 97 `time.Sleep(` calls in 39 `_test.go` files; the lines cited in `interface_test.go` are right.
- Can be split by package if it grows.

## Log
- 2026-11-07 created in backlog
- 2026-11-07 milestone → later (owner's MVP cut: flake hygiene)
