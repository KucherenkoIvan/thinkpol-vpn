---
id: TP-161
title: "macOS guard: check that pf still lists the guard's reference while pf is on"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: M
depends_on: [TP-137]
refs: [RR11]
needs_human: decision
owner: ""
branch: ""
---

## Goal
When pf is on and the guard's reference has vanished from pf's list, the guard notices, kills what pf passed while off, and takes a new reference, so RR11's "comes and goes between two polls" no longer covers someone else's `pfctl -d` followed by another program's `pfctl -e`.

## Scope
- With pf on and a known token, `enable` (internal/dataplane/firewall/guard_darwin.go, TP-137's branch) only re-records the token, and the poll (`broken`) only checks that pf is on. Neither checks that pf still lists the guard's reference.
- If someone runs `pfctl -d` and another program runs `pfctl -e` within one poll, two things go wrong:
  - states made while pf was off survive;
  - the guard thinks it holds a reference it doesn't, so pf goes off when the other enabler releases its own.
- A vanished reference is lasting evidence that pf was off. Check it in `enable`, and in the poll if the extra run is worth it: anything other than `refOurs` → `statesStale` + `takeReference`. That costs one more pfctl run per poll.
- It needs a decision on the unreadable-listing case: treat it as vanished (take a reference, possibly two held), as present (today's behaviour), or as a failure the poll reports.
- Update RR11's macOS text and the package doc to match.

## Out of scope
- A failed record write losing the old reference: TP-159. pf off with a pid-only reference and an unreadable listing: TP-160.
- A change that comes and goes between two polls and leaves no lasting trace stays in RR11.

## Acceptance
- [ ] the decision on the unreadable listing (and on checking in the poll as well as in `enable`) is in Notes
- [ ] TP-137's TestAChangeOnlyThePollSawKills, or a new test after it, asserts the end state it leaves unchecked today: after `pfctl -d` and someone else's `pfctl -e`, the next Apply kills the states made meanwhile and the guard holds a reference pf lists. Mutation: dropping the listing check fails it
- [ ] RR11 and doc.go say what this narrows
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-137 round-1 reviews and implementer, 2026-10-29.
- TP-137's TestAChangeOnlyThePollSawKills already ends in this state (pf disabled, then turned on plainly) without asserting it.
- Read the code with `git show origin/tp-137-macos-guard-kills-states-without-a-token:internal/dataplane/firewall/guard_darwin.go` until TP-137 merges.

## Log
- 2026-10-29 created in backlog (TP-137 round-1 review)
