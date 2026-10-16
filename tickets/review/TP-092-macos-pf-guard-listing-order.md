---
id: TP-092
title: "macOS pf guard: load without pfctl's rule optimizer"
milestone: M1
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-078]
refs: [DESIGN#ipv6]
needs_human: macos
owner: "glm-tp092"
branch: "tp-092-macos-pf-guard-listing-order"
---

## Goal
On a real Mac the IPv6 leak guard loads and is enforced. In TP-078's first device session it never was: the guard's check of pfctl's listing refused every load, so health said `ipv6_guard_not_enforced` from the start.

## Scope
- Load the guard's anchor with pfctl's rule optimizer off (`-o none`), so pf keeps the rules in the order and shape they were written. pf.conf(5)'s default, `basic`, re-orders rules and may merge rules into a table, and `saneRules` (`internal/dataplane/firewall/pfctl_darwin.go`) rightly expects neither.
- Keep `saneRules`' order check: the guard's quick rules are an ordered decision, so an unexpected listing should still refuse the load.
- Make the fake pfctl (`fakepf_darwin_test.go`) re-order the rules like `-o basic` when a load lacks `-o none`, so the test fails without the fix.
- Log every failed guard apply at WARN, not just the first, rate-limited (for example once a minute with a count), so a guard that keeps failing is visible in the log as well as in the health.

## Out of scope
- Other device findings (TP-093, TP-094).

## Acceptance
- [x] a test using the device's listing below fails before the fix and passes after it
- [x] the fake pfctl re-orders without `-o none`, and a test proves the guard then refuses
- [x] `make lint` and `make test` pass
- [x] device session B on the TP-092 build: health shows no `ipv6_guard_*` problem and no guard failure is logged (08/09/10 need native IPv6: moved to TP-096)

## Notes
- **Device evidence (2026-10-16, TP-078 session A).** At start the agent logged once: `route table: applying the leak guard failed, retrying … err="firewall: pf lists the guard's rule 1 as \"pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type groupqry no state\", without \"on\""`. The first status a minute later had health `ipv6_guard_not_enforced`, and no later WARN appeared. pfctl listed the multicast rule first, where `pass out quick on lo0 inet6 all no state` was loaded first.
- **Inference to confirm on the device.** pf.conf(5) says the `basic` optimizer (the default) removes duplicate rules, removes subsets, combines rules into tables and re-orders rules. That ordering is the likeliest cause. Session B confirms it, or says otherwise.
- **Why this is a new ticket:** TP-078 used its 3 review rounds. This ticket is cut from TP-078's head, and TP-078 and TP-092 merge together after session B passes.

## Review findings
- [x] S1 the docs stated the fix as device-confirmed before any device ran it: now cites session B
- [ ] N1-N5 (cancelled context starts the warn window; suppressed count dropped on success; ICMPv6 names for 131/132 in the fake; the source-scan test; argv-position assertion): moved to TP-095

## Log
- 2026-10-16 created in backlog (TP-078 device session A)
- 2026-10-16 backlog → in-progress (owner glm-tp092)
- 2026-10-16 in-progress → review. The guard's one load path (`load`, guard_darwin.go) now passes `-o none`; a source test (TestEveryLoadCarriesNoOptimizer) fails if a load line ever drops it. The fake pfctl reorders a load without `-o none` the way the device saw (the multicast rules listed first) and names ICMPv6 type 130 `groupqry`, and it no longer shortens `from any to` — the device's listing kept it (one test assertion updated). Tests added: TestApplyLoadsUnoptimized, TestAnOptimizedLoadIsRefused (the device's error text exactly), TestTheFakeOptimizesALoadWithoutNone, TestEveryLoadCarriesNoOptimizer; routetable: every failed guard apply warns at most once a minute with the silenced count (TestGuardFailuresAreWarnedAtMostAMinuteApart, an injected clock — the package had none, so a `now` func on the Enforcer). Planted bug (the `-o none` removed): 15 firewall tests failed, TestAnOptimizedLoadIsRefused printed the device's error text verbatim; the fix restored, all green. `make lint` and `make test` pass; the pfctl tripwire holds (no test runs the real pfctl). Only a real Mac can verify: that pfctl accepts `-o none` on an anchor load and lists unoptimized (pf.conf(5) says it does; session B), and that macOS's pfctl prints the other expanded rules the way the fake guesses (`listenrep`, `listendone`, 143, and `from any to` on the non-multicast rules — only the groupqry rule is device-evidenced).
- 2026-10-16 device session B recorded; review S1 fixed; nits to TP-095
