---
id: TP-095
title: "macOS pf guard follow-ups"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-092]
refs: [DESIGN#ipv6]
owner: "agent-tp-095"
branch: "tp-095-macos-pf-guard-follow-ups"
---

## Goal
Tidy up the macOS pf IPv6 leak guard's failure paths and test nits left from TP-078 and TP-092 device sessions and review.

## Scope
1. A load that `saneRules` or the table check refuses: decide between flushing the anchor and keeping the unverified rules (they still block IPv6), document the choice in DESIGN.md, and cover it with a test.
2. `applyGuard` skips the warn window for an Apply that failed because its context was cancelled (`routetable.go` around 546–560).
3. A success after silenced failures logs the suppressed count once.
4. The fake's ICMPv6 names for 131 and 132: check pfctl's icmp6 type table (first match per number) and fix.
5. Delete `TestEveryLoadCarriesNoOptimizer` (a source scan; the fake's reordering already proves the behaviour).
6. Delete `TestApplyLoadsUnoptimized` and `TestTheFakeOptimizesALoadWithoutNone`. They re-prove `TestApplyPutsTheGuardInPlace` and `TestAnOptimizedLoadIsRefused` now that the fake reorders loads without `-o none`, and what's left of them asserts call sequences.
7. Redaction: the guard's WARN logs pfctl's raw error, and a `saneRules` error can quote a DNS upstream's address, while the route table's own warnings redact (`path.RedactError`, because logs may leave the device). Either redact, or keep the rule text on purpose (it is what diagnosed TP-092), say why in a comment, and redact the addresses in it.
8. Make the rate limiter a small reusable type (`warnLimit`: allow/reset), and use it for the route table's re-apply warnings too (`routetable.go` around 621, 639 and 729), which warn every `RetryAfter` forever.
9. Comments and DESIGN.md state constraints, not history:
   - `guard_darwin.go:201-205` and `:26-27`;
   - the fake's `withoutNone` comment and the dated "`from any to`" comment;
   - DESIGN.md:157's parenthetical with a session date: the evidence belongs in TP-078/TP-092.
   Fix the fake's comment, which says only the listing is reordered (`basic` reorders the ruleset pf evaluates). Rename `fakeOptimize`, or say it reproduces only the reordering seen on the device.
10. `Enforcer.now`: declare it with the other construction-time fields, and set it before the watcher goroutine starts (for example an unexported `openWithClock` that `OpenWithGuard` calls). Use one style in `export_test.go`. The rate-limit test advances by the limit itself, not by `RetryAfter * 12`.

## Out of scope
Device runs on a network with native IPv6 (TP-096).

## Acceptance
- [x] scope item 1: DESIGN states the behaviour and a test covers it
- [x] scope item 2: a test covers cancelled-context Apply and the warn window
- [x] scope item 3: a test covers suppressed-count logging on success
- [x] scope item 4: a test covers ICMPv6 131/132 names in the fake
- [x] scope item 5: `TestEveryLoadCarriesNoOptimizer` removed
- [x] scope item 6: both tests removed, and planting the bug (no `-o none`) still fails the remaining tests
- [x] scope item 7: a test shows what the guard's WARN prints for a refused load with an upstream rule
- [x] scope item 8: a test per warn site that uses the limiter
- [x] scope items 9 and 10: done; the review checks them
- [x] `make lint` and `make test` pass

## Notes

## Log
- 2026-10-16 created (TP-078/TP-092 device sessions)
- 2026-10-16 docs: TP-092's design review findings (S1-S6, N1-N6) added as scope 6-10; Grok's second opinion found nothing beyond this list
- 2026-10-21 backlog → in-progress — owner: agent-tp-095, branch: tp-095-macos-pf-guard-follow-ups
- 2026-10-21 scope 1 decision: a load pfctl takes but saneRules or the table check refuses stays in pf, not flushed. Why: the guard's purpose is that IPv6 never leaks; an empty anchor passes all IPv6, while the unverified rules still end in the block, so keeping them is never less strict than flushing. pf isn't enabled for them (only a guard read back whole takes a reference); the Apply fails and is retried. DESIGN.md "The leak guard on macOS" and the Apply comment say so. TestARefusedLoadStaysInPlace (mutation: flushing the anchor on a refused load fails both subtests)
- 2026-10-21 scope 2: applyGuard warns only while its context is live, and a cancelled Apply doesn't count against the window. TestACancelledGuardApplyIsNotWarned (mutations: warning regardless fails it; a cancelled Apply taking the window fails it)
- 2026-10-21 scope 3: when a failure clears, one INFO line says how many warns were held back (suppressed=N), at every limited site. TestAGuardSuccessSaysHowManyFailuresWereHeldBack, plus the per-site test (mutations: never logging, logging with nothing held back: both fail)
- 2026-10-21 scope 4: pfctl's icmp6 type table read from the order of the names in the system pfctl binary's strings (not run): groupqry, listqry, grouprep, listenrep, groupterm, listendone; first match gives 131 grouprep, 132 groupterm; no listenrepv2, so 143 stays a number. TestTheFakeNamesICMPv6TypesAsPfctl (mutation: the old names fail it)
- 2026-10-21 scope 5, 6: the three tests removed; planting the bug (load without -o none) fails 23 remaining tests, TestApplyPutsTheGuardInPlace and TestAnOptimizedLoadIsRefused among them
- 2026-10-21 scope 7 decision: keep the rule text and redact its addresses. Why: the listed rule's order and shape are what diagnosed TP-092, and the addresses are the only part that identifies anything. Every retried warn goes through path.RedactError in warnRetry, and so does the unsupported warn. saneRules' comment says why. TestTheWarnOfARefusedLoadQuotesTheRuleWithoutItsAddresses shows the whole line (mutation: no redaction fails it)
- 2026-10-21 scope 8: warnLimit (allow/reset) in routetable/warnlimit.go is used by the guard's apply, the re-apply, watching routes and watching the guard. watch is split exactly as TP-083 splits it (watches, subscribe, subscribeGuard, backstop), so the warn sites are methods. TestRetriedFailuresAreWarnedAtMostOnceAMinute (one subtest per site) and TestGuardFailuresAreWarnedAtMostAMinuteApart (mutations: a fresh limiter per warn, or no reset, at each of the 4 sites fails that site's test)
- 2026-10-21 scope 9, 10: comments state constraints (load, the IPv6Guard doc, the fake's withoutNone, reorderLikeBasic (was fakeOptimize: it reorders the ruleset, and only the way it did the guard's), fakeExpand); DESIGN's "(TP-092)" dropped. Enforcer.now sits with the construction-time fields, and openWithClock sets it before the watcher starts; export_test.go helpers are all functions; the rate-limit test advances by WarnEvery (mutations: a `<=` window, openWithClock ignoring its clock: both fail it)
- 2026-10-21 checks: make lint and make test green before each commit. funlen with TP-083's config on routetable and firewall flags only splitRoutes and Linux Watch, which TP-083 splits and this branch doesn't touch. Merged origin/rewrite (TP-112). make lab-test (LAB_P=1, other labs running) green on 5d0fcfc
- 2026-10-21 not verified: real pfctl on a device (no pfctl run): the 131/132 names in a live listing, and a refused load staying in place. Expect a conflict in routetable.go when TP-083 lands: the watch split is identical, but the warn lines in subscribe and subscribeGuard differ, and TP-083's Error* codes are untouched here
- 2026-10-21 out of scope (for the orchestrator): a refused reload replaces the previous, verified guard with the unverified one, which may exempt more if its table grew (the table check refuses then); reloading the last good guard would close that
