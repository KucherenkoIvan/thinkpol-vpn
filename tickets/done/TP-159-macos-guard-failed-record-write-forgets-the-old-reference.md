---
id: TP-159
title: "macOS guard: a failed record write in takeReference forgets the old reference"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-137]
refs: [RR11]
owner: "agent-tp-159-fix1"
branch: "tp-159-macos-guard-failed-record-write-forgets-the-old-reference"
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
- [x] a unit test with the fake pfctl: the guard holds a reference that pf still lists, pf is found off, `-E` succeeds and the record write fails; after a later Apply that succeeds, and after Close, pf lists neither reference. Mutation: returning before the old reference is kept or released fails it
- [x] doc.go's "never held unrecorded or forgotten" holds for this path, and the doc says how
- [x] `make lint`, `make test` pass

## Notes
- Source: TP-137 round-1 reviews and implementer, 2026-10-29.
- Read the code with `git show origin/tp-137-macos-guard-kills-states-without-a-token:internal/dataplane/firewall/guard_darwin.go` until TP-137 merges.
- Fix chosen: the pending-release slot (`IPv6Guard.owed`). takeReference adds the old reference to it right after `-E`, before the record write; `releaseOwed` runs once the record names the new reference (in takeReference, or in enable's later record retry), and Close releases owed references after the guard's own one. A release that fails (unreadable References, pfctl failing, ctx cancelled) is told after and keeps the reference owed, for the next Apply or Close (round 1, R1.2). Close releases owed references before its own, so pf stays on by the guard's reference while they go (R1.4). adoptRecord never takes an owed reference over as the guard's own (R1.3). Owed references live in memory only. The record is replaced atomically, so a failed write leaves it naming the old reference: after a crash the next start's routetable.Clear releases the old one through the record, and the new, unrecorded reference stays with pf (as do older owed ones after more than one failed write).

## Review findings
- [x] R1.1 doc.go:383-384 and the Notes describe a crash backwards: the record write is atomic, so a failed write leaves the record naming the old reference T1, and the next start's Clear releases T1; the reference left with pf after a crash is the new, unrecorded T2. Correct both texts.
- [x] R1.2 guard_darwin.go:824-833: releaseOwed empties g.owed even when a release fails (unreadable References listing, pfctl timeout, cancelled ctx). Keep the entries whose release fails, so a later Apply or Close retries them, as the Scope says. Update the test at guard_darwin_test.go:~1997 and add a failed release followed by a successful retry.
- [x] R1.3 adoptRecord (guard_darwin.go:725-739, with :714) can adopt a reference already in g.owed, and releaseOwed then releases the guard's own token. Skip owed tokens, with a test: write fails with T1 owed; the guard's token disappears; -E fails; pf is on from elsewhere; the next Apply.
- [x] R1.4 Close releases its own reference before the owed ones (guard_darwin.go:1013-1023). Release the owed references first, so pf can never turn off while an owed -X is pending. Test: Close with a failing owed release keeps it, and a second Close retries it.

## Log
- 2026-10-29 created in backlog (TP-137 round-1 review)
- 2026-10-31 backlog → in-progress, owner: agent-tp-159
- 2026-10-31 owed slot: guard_darwin.go (owed field, releaseOwed, takeReference keeps old before the record write, enable releases owed after a retried write, Close releases owed); doc.go "enabling pf by reference" says what happens on a failed write and drops the TP-159 carve-out
- 2026-10-31 test TestAFailedRecordWriteKeepsTheOldReferenceOwed (subtests Apply, Close): keepRefs fake, pf found off, -E ok, record dir 0500 → Apply fails; then a good Apply leaves one recorded reference, and Close leaves none. Mutations, each fails it: old kept only after the record write (rewrite's order); rewrite's guard_darwin.go as-is; Close skipping owed; enable's record retry not releasing owed
- 2026-10-31 make lint, make test green on 9c9358b. No lab run: darwin-only change, the lab runs Linux. Not verified: whether XNU keeps references listed after pfctl -d (device check, out of scope)
- 2026-10-31 out of scope: an Apply's failed release of the old reference still drops it (told, "left to pf"); doc.go now says so, but it is the same forgetting class this ticket closed for the write path; a follow-up could keep it owed until Close
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 4 should-fix)
- 2026-10-31 has-errors → in-progress, owner: agent-tp-159-fix1
- 2026-10-31 R1.1: doc.go "enabling pf by reference" and Notes now say a failed write leaves the record naming the old reference (atomic replace), so after a crash Clear releases the old one and the new one stays with pf unrecorded. Closing that leak is not trivial (the record can't name a reference before -E returns it); not built
- 2026-10-31 R1.2: releaseOwed keeps references whose release fails; TestAFailedReleaseOfTheOldReferenceIsTold now clears the fault, re-Applies (old released, guard whole) and Closes (gone). Mutation: g.owed = nil restored fails it
- 2026-10-31 R1.3: adoptRecord skips a record that names an owed reference; TestAnOwedReferenceIsNotTakenOverFromTheRecord (failed write with noToken+oddReferences, the new pid-only reference removed, -E fails, another program's reference, then Apply: guard whole beside theirs, the owed one released, Close leaves theirs only). Mutation: the owed case removed fails it
- 2026-10-31 R1.4: Close releases owed references before its own; TestCloseKeepsAnOwedReferenceItCantRelease (-X of the owed token fails: Close fails with both references listed; second Close leaves none). Mutations, each fails it: own reference released first; Close dropping the owed entry before checking the release error
- 2026-10-31 failedRecordWrite helper shared by the new tests and TestAFailedRecordWriteKeepsTheOldReferenceOwed; it also checks the record still names the old reference after the failed write. Nits: re-wrapped the long lines at doc.go and the Close comment
- 2026-10-31 make lint, make test green. No lab run: darwin-only change, the lab runs Linux
- 2026-10-31 in-progress → review
