---
id: TP-164
title: "macOS guard: owed references, the leftovers"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-159]
refs: [RR11]
owner: ""
branch: ""
---

## Goal
The owed-reference slot TP-159 added never releases the guard's own reference, and its failure modes are either documented or don't fail the guard while it enforces.

## Scope
- (a) `adoptRecord` (internal/dataplane/firewall/guard_darwin.go:726-744) skips a record naming an owed reference with `slices.Contains(g.owed, t)` (:734), an exact match on `pfToken{value, pid}`. An owed reference known by its pid only (`{0, pid}`) doesn't match a record of the same reference with its value resolved, so the guard can adopt it as its own, and `releaseOwed` (:829-840) then releases the guard's own reference. Suggested fix: when the owed entry's value is 0, match by pid. Check the reverse case (record by pid only, owed with a value) too.
- (b) An owed release that keeps failing (an unreadable References listing: `release`, :859, returns `errUnreadReferences`) is returned by every Apply (`enable`'s `releaseOwed` calls, :706, :714, :815), so every Apply fails, and each poll marks the guard not enforced while the anchor is loaded and pf enforces it. Nothing documents that. Either document it in doc.go ("enabling pf by reference") or don't fail the Apply for an owed release alone (tell it some other way). Say which in Notes.
- (c) Pre-existing: Close (:993-1034) with no own reference, pf off and an owed reference still listed fails on every call. It releases owed references first, and pf refuses `-X` while it is off. Close never succeeds, so the guard and its record stay for the next run's `routetable.Clear`. Decide whether Close should treat that reference as gone or turn pf on to release it, and pin the choice with a test.

## Out of scope
- pf off with a pid-only reference and an unreadable listing: TP-160. Checking that pf still lists the guard's reference while on: TP-161. Both wait on owner decisions; this ticket doesn't make them.
- Whether XNU keeps references listed after `pfctl -d`: a device check.

## Acceptance
- [ ] (a) a unit test with the fake pfctl: an owed reference known by pid only and a record naming the same reference with its value; the next Apply doesn't adopt it, and the guard's own reference is still listed afterwards. Mutation: the exact match back fails it
- [ ] (b) a failing owed release either no longer fails the Apply (with a test showing the guard enforced and the release retried) or is documented in doc.go with what the caller sees
- [ ] (c) a test of Close with no own reference, pf off and an owed reference listed, pinning the chosen behaviour; doc.go says it
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-159's final check (tickets/done/TP-159-macos-guard-failed-record-write-forgets-the-old-reference.md, last Log line): two nits left for a follow-up, (a) and (b). (c) was found while reading Close for them.
- Same area as TP-160 and TP-161. Don't decide either here, and keep the changes small enough to rebase onto whatever they choose.
- darwin-only: the lab runs Linux, so the fake pfctl is the test bed.

## Log
- 2026-10-31 created in backlog (TP-159 final check)
