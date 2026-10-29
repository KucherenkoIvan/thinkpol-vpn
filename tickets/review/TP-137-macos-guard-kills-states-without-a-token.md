---
id: TP-137
title: "macOS guard: kill the states pf passed while off even when the new token can't be read"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: [D6, docs/design/security.md#ipv6]
owner: "agent-claude-tp137"
branch: "tp-137-macos-guard-kills-states-without-a-token"
---

## Goal
When pf was turned off under the guard, the Apply that turns it back on kills the IPv6 states made while it was off, even if `pfctl -E`'s token can't be read.

## Scope
- Today `takeReference` returns `errUnreadToken` when `pfctl -E` prints no token that `pfctl -s References` can name, and `Apply` (`firewall/guard_darwin.go`) returns at once, before the bypass check and the state kill. Each retry meets the same error in `resolveToken` for as long as the token stays unnamed, so states pf passed while it was off keep passing.
- Let `Apply` carry on through the bypass check and the kill after `errUnreadToken`, and report it at the end, as TP-091's round 4 did for a failed release of the old reference. Say so in firewall/doc.go.
- Dates from TP-078; it changes the guard's behaviour, so it isn't part of TP-091.

## Acceptance
- [x] a test: with the new token unreadable, a state made while pf was off is killed in the same Apply, and the Apply still returns `errUnreadToken`; it fails if Apply returns early
- [x] firewall/doc.go says the Apply finishes enforcing, then reports the unread token
- [x] `make lint`, `make test` pass

## Notes
- From TP-091's round-5 design review (2026-10-23).
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Guard lane: last, after TP-129 (the same two pf files).

## Review findings
Round 1 (2026-10-29): paranoid (merge), pocket-torvalds (fix first: S1–S3, nits 1–6); the cross-family (Cursor) review didn't complete: its log was empty. Folded in as one round, merged without a further review round.
- [x] R1.1 (torvalds S1) the poll read pf's status only on a whole guard. A persistent bypass keeps the guard failing (its kill done under that bypass), so `broken` returned at `failing` and pf off went unmarked; someone's `pfctl -e` before the next Apply left the states pf passed while off alive. `broken` now reads pf's status first, failing guard included, and marks the states stale when pf is off (torvalds' placement, after the bypass check, would still have returned at `failing` first). Test: a pf-off-under-a-bypass case in TestAChangeOnlyThePollSawKills.
- [x] R1.2 (torvalds S2) Apply ends `return errors.Join(err, after)`, no `later` slice.
- [x] R1.3 (torvalds S3) enable's carry-on branch names its error `rerr`.
- [x] R1.4 (torvalds nits 1–4) comments: enable's statesStale (pf off is marked above), killStates points at statesStale, the type doc's "or no longer lists its pid", takeReference's after/err.
- [x] R1.5 (torvalds nit 5, paranoid nit 2) takeReference keeps resolve's error: the unread-token error says why pf's listing didn't name the token (unreadToken; resolve's own errUnreadToken isn't told twice). Tests: TestAnUnreadableTokenIsNotTakenTwice ("not found yet" asserts errUnreadReferences and one token message; new "the listing failed").
- [x] R1.6 (torvalds nit 6) RR11 gets the pid-only line, naming TP-160.
- [x] R1.7 (paranoid nit 1) doc.go says the poll reads pf's status first, a failing guard's too, and that a failing guard's 5 s retries read it anyway; the polling section says pf's status is read first and pf off or a failed apply ends the poll.
- [x] R1.8 (out of scope, filed) paranoid's should-fix A → TP-159; the implementer's two findings → TP-160, TP-161; doc.go names each where it describes the case.

## Log
- 2026-10-23 created in backlog (TP-091 review round 5)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Guard)
- 2026-10-29 backlog → in-progress, owner: agent-claude-tp137
- 2026-10-29 done: Apply carries on after errUnreadToken only while pf is known on, decided inside enable, where pf's status is read before the token (the one-liner in Apply would also have carried on for resolveToken's errUnreadToken with pf off). Two sources: takeReference after `-E` (pf on by it; the error joins a failed old release in enable's `after`), and resolveToken with pf on (a reference known by pid only; the record is written there too, so a failed write is retried). With pf off, Apply still stops at the token, before the check and the kill. pf seen off, by an Apply or a poll, marks the states stale, so the Apply after someone else's `pfctl -e` kills what pf passed while off. firewall/doc.go (token and kill sections) and RR11 updated.
- 2026-10-29 tests: TestAnUnreadTokenStillKills (the acceptance test, plus retries: nothing changed doesn't kill again, a bypass is told with the token and kills), TestAnUnreadTokenWithPfOffStopsTheApply (pf off: no carry-on, no second reference; pf back on by someone else: both states made while off killed), TestAnUnreadTokenIsRecordedOnTheRetry, and a pf-off case in TestAChangeOnlyThePollSawKills. Mutants, each run and failing: takeReference returning the unread token as err (StillKills); carrying on whatever pf's status (PfOff); no statesStale for pf seen off in enable (PfOff); no carry-on after resolveToken (StillKills, PfOff, IsRecordedOnTheRetry); carrying on without recordToken (IsRecordedOnTheRetry); Apply dropping enable's after (StillKills, PfOff, IsRecordedOnTheRetry and existing token tests); no statesStale for pf seen off in the poll (AChangeOnlyThePollSawKills).
- 2026-10-29 make lint, make test green; make lab-test (LAB_P=4) green on 8220cc0, 36 packages in the node. The lab is Linux: it builds and runs the Linux guard and everything else, not the darwin pf code, which only the fake pfctl tests here cover. Not verified: real pfctl on a Mac (no device run), in particular a real `pfctl -E` without a readable token.
- 2026-10-29 in-progress → review
- 2026-10-29 round 1 fixes (R1.1–R1.8, 75c3ff3). Mutants, each run and failing: no status read on a failing guard (`if g.failing { return true }` before it; AChangeOnlyThePollSawKills, the pf-off-under-a-bypass case); no statesStale for pf off in the poll (AChangeOnlyThePollSawKills, both pf-off cases); takeReference dropping resolve's error (IsNotTakenTwice/not found yet); unreadToken without its case for resolve's errUnreadToken (IsNotTakenTwice/not found yet: the token told twice); unreadToken without its case for a failed listing run (IsNotTakenTwice/the listing failed).
- 2026-10-29 merged origin/rewrite (5c3bc14: TP-159…TP-161 filed); make lint, make test green; make lab-test (LAB_P=4) green on 7ce271b, 36 packages in the node. The lab is Linux: it doesn't run the darwin pf code, which only the fake pfctl tests cover. Not verified: real pfctl on a Mac (no device run).
