---
id: TP-160
title: "macOS guard: pf off, a pid-only reference and an unreadable References listing keep IPv6 unguarded"
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
The owner decides what happens when pf is found off while the guard knows its reference by pid only and `pfctl -s References` can't be read, and either the code or RESIDUAL-RISKS.md covers it.

## Scope
- In `enable` (internal/dataplane/firewall/guard_darwin.go, TP-137's branch), `resolveToken` fails with `errUnreadToken` when the listing can't be read. With pf off, `enable` returns that as err before `takeReference`, and every retry stops at the same place. pf stays off and IPv6 goes unguarded for as long as the listing format stays unreadable. Health reports the failure, but RESIDUAL-RISKS.md has no row for it.
- Options for the owner:
  - **`-E` anyway and record two references.** pf comes back on. This changes the record format (it holds two references), and the nameless reference may leave pf on after Close, because the guard can't release a token it can't read.
  - **Accept it** with its own RESIDUAL-RISKS.md row (what fails, for how long, what health shows, why it is accepted).
- Agents prepare a short comparison with a recommendation; the owner picks. Then implement the pick and update doc.go's "enabling pf by reference" section ("pf stays off until ...") to match.

## Out of scope
- A failed record write losing the old reference: TP-159. Checking that pf still lists a known token: TP-161.
- Making the References parser read more formats: separate work if a real format turns up.

## Acceptance
- [ ] the owner's decision and its reasons are in Notes
- [ ] if `-E` anyway: a unit test with the fake pfctl (pf off, pid-only reference, unreadable listing) shows pf on after Apply, both references recorded, and Close releasing every one it can name; the record format change has a reader for the old format or a reason it doesn't need one
- [ ] if accepted: a RESIDUAL-RISKS.md row for it, linked from doc.go, and the PRD requirement its Breaks column names says so
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-137 round-1 reviews and implementer, 2026-10-29.
- Read the code with `git show origin/tp-137-macos-guard-kills-states-without-a-token:internal/dataplane/firewall/guard_darwin.go` until TP-137 merges.

## Log
- 2026-10-29 created in backlog (TP-137 round-1 review)
