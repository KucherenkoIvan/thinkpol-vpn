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
- [ ] scope item 1: DESIGN states the behaviour and a test covers it
- [ ] scope item 2: a test covers cancelled-context Apply and the warn window
- [ ] scope item 3: a test covers suppressed-count logging on success
- [ ] scope item 4: a test covers ICMPv6 131/132 names in the fake
- [ ] scope item 5: `TestEveryLoadCarriesNoOptimizer` removed
- [ ] scope item 6: both tests removed, and planting the bug (no `-o none`) still fails the remaining tests
- [ ] scope item 7: a test shows what the guard's WARN prints for a refused load with an upstream rule
- [ ] scope item 8: a test per warn site that uses the limiter
- [ ] scope items 9 and 10: done; the review checks them
- [ ] `make lint` and `make test` pass

## Notes

## Log
- 2026-10-16 created (TP-078/TP-092 device sessions)
- 2026-10-16 docs: TP-092's design review findings (S1-S6, N1-N6) added as scope 6-10; Grok's second opinion found nothing beyond this list
- 2026-10-21 backlog → in-progress — owner: agent-tp-095, branch: tp-095-macos-pf-guard-follow-ups
