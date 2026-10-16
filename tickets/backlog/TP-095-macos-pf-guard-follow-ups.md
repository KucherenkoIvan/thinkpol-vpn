---
id: TP-095
title: "macOS pf guard follow-ups"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-092]
refs: [DESIGN#ipv6]
owner: ""
branch: ""
---

## Goal
Tidy up the macOS pf IPv6 leak guard's failure paths and test nits left from TP-078 and TP-092 device sessions and review.

## Scope
1. A load that `saneRules` or the table check refuses: decide between flushing the anchor and keeping the unverified rules (they still block IPv6), document the choice in DESIGN.md, and cover it with a test.
2. `applyGuard` skips the warn window for an Apply that failed because its context was cancelled (`routetable.go` around 546–560).
3. A success after silenced failures logs the suppressed count once.
4. The fake's ICMPv6 names for 131 and 132: check pfctl's icmp6 type table (first match per number) and fix.
5. Delete `TestEveryLoadCarriesNoOptimizer` (a source scan; the fake's reordering already proves the behaviour).
6. `TestApplyLoadsUnoptimized` checks that `-o` is followed by `none` anywhere in the argv.

## Out of scope
Device runs on a network with native IPv6 (TP-096).

## Acceptance
- [ ] scope item 1: DESIGN states the behaviour and a test covers it
- [ ] scope item 2: a test covers cancelled-context Apply and the warn window
- [ ] scope item 3: a test covers suppressed-count logging on success
- [ ] scope item 4: a test covers ICMPv6 131/132 names in the fake
- [ ] scope item 5: `TestEveryLoadCarriesNoOptimizer` removed
- [ ] scope item 6: `TestApplyLoadsUnoptimized` asserts `-o` then `none` in argv
- [ ] `make lint` and `make test` pass

## Notes

## Log
- 2026-10-16 created (TP-078/TP-092 device sessions)
