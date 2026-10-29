---
id: TP-127
title: "IPv6 guard: a failed shrink of the direct set still narrows the guard"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/routing.md#routing-rules-and-dns]
owner: "agent-claude-tp127"
branch: "tp-127-guard-follows-a-failed-shrink"
---

## Goal
When a smaller direct set fails to apply, and so does the fallback to nothing direct, IPv6 to the dropped prefixes is refused instead of going direct.

## Scope
- Today the guard is held to the routes still in place (`routetable` doc, "the guard follows the routes"). That is right when the new guard would be *wider* than the routes. When the new direct set is a *subset* of the old one, a narrower guard can only block, never leak. So on a failed shrink, apply the guard for the new direct set while the routes stay the old ones.
- IPv4 to the dropped prefixes keeps going direct until an Apply works. That part stays with the kill switch (TP-048).
- Health keeps saying the routes failed. Once this lands, the residual-risks row for a failed shrink (TP-077's RESIDUAL-RISKS.md) drops D6 and names this ticket for IPv6.

## Acceptance
- [x] a test where removing direct prefixes fails and so does the fallback: the guard installed is the new, narrower set's, and the routes are the old ones. Mutation: holding the guard to the old routes fails it
- [x] a test that a failed *grow* still holds the guard to the routes in place (no wider guard than the routes)
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-077's round-2 design review (2026-10-22): the row had no ticket. It breaks D6 (a must), and the subset case allows a fail-closed fix.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Guard lane: after TP-138, before TP-129 (the same two pf files).
- **Decision (2026-10-28): while an Apply fails, the guard is the intersection.** Where: `routetable.Enforcer`, the one place that picks the guard's Exempt after a failed Apply (`apply`'s failure branch, and `reapplyGuard` for the guard's own repairs); `guardWhileFailing(held, w)` is `GuardFor(held)` with Direct cut to what `GuardFor(w)` exempts too. Never wider than the routes in place (held), nor than the rules (w). The cases: a failed shrink (w ⊂ held) gives w's guard, so IPv6 to the dropped prefixes is refused; a failed grow (held ⊂ w) keeps held's; a mixed change (some added, some dropped) exempts only the prefixes both keep: an added one has no route yet (into the TUN anyway), a dropped one is what the rules now tunnel (refused). Endpoints are part of GuardFor's Direct and intersect the same way. ~~Upstreams, TUN and Mark stay held's (the routes in place).~~ TUN and Mark stay held's; Upstreams intersect too (revised below). The engine's fallback to nothing direct, when it fails too, narrows the guard to the endpoints alone until the engine's next step (the new rules' Want) narrows it to old ∩ new; if the router change fails in between, the guard stays at the endpoints while the fallback is retried: fail closed, the fallback's own intent. The guard's adapters reload on any change of Exempt and the pf one kills states it no longer exempts, so no firewall change is needed. Forwarded IPv6 (containers, VMs) isn't the guard's: it follows the old routes' throws like IPv4, so RR14 keeps D6 for forwarded IPv6 only (2026-10-29, takeover; scoped to Linux in round 1, below).
- **Decision revised (2026-10-29, review round 1, orchestrator).** (1) One rule: `guardFor(held, want)` (was `guardWhileFailing`) picks the guard in `apply` and `reapplyGuard` alike, and `failing` no longer selects it anywhere: with held == want it is `GuardFor(want)`, so no branch is needed, and TP-148, which changes the retry logic next, can't change which guard goes in. `apply` records `want`/`applied` first, then applies the guard from that state. (2) Upstreams are intersected too, which reverses "Upstreams stay held's": that left a failing Want that drops an upstream (the system's resolvers moved) with macOS's pf still exempting DNS to the old address and port for any socket (RR13), wider than the rules, and made routing.md's "never wider than the routes in place nor than the rules" false. An upstream added has no scoped route yet, so refusing it fails closed, as for Direct, and costs our resolver nothing (it has already switched). (3) Forwarded IPv6 going direct is Linux's (the nftables guard hooks output only); macOS's pf filters forwarded packets on the way out, so it probably refuses them: unverified, TP-096. (4) The intersection is `lists.Set.Intersect`, exported: the engine's shrink computes the same set (`old ∩ direct`) and now uses it.

## Review findings
Round 1 (2026-10-29): go-paranoid no proven defect, should-fix 1–2; pocket-torvalds fix first (S1–S8); go-style fix first (1–3). The cross-family review (Cursor) failed to connect; it runs in round 2.
- [x] R1.1 (torvalds S1): one rule. A single `guardFor(held, want)` picks the guard in `apply` and `reapplyGuard`; `failing` no longer selects it anywhere (TP-148 changes the retry logic next). `apply` updates `want`/`applied` first, then applies the guard from that state. Done: `guardFor` in routetable.go; `apply` sets `want`/`applied` then applies `guardFor(*held, w)`; `reapplyGuard` applies `guardFor(*held, *want)`; `failing` is read only by the retry logic and Enforce's no-op check.
- [x] R1.2 (torvalds S2; go-style 5): `Minus(Minus(...))` is an intersection in disguise. Add an exported `lists.Set.Intersect` with its own tests (symmetry, nil on either side, a /32 against a /48 inside it). Exported rather than go-style's unexported helper: torvalds' case is that the engine computes the same thing another way (`old.Minus(gone)`), so it is not routetable's alone. Done: `Set.Intersect` in set.go, `TestIntersect` (every address of small universes, symmetry, nil, self, a partial overlap across families); lists' doc lists it; the engine's shrink uses `old.Intersect(direct)`.
- [x] R1.3 (torvalds S3 = paranoid 3 = go-style 1): Upstreams are intersected too, so routing.md's "never wider than the routes in place nor than the rules" is true as written. The Notes decision "Upstreams stay held's" is revised. Done: `intersectUpstreams`; Notes decision revised (above); routing.md and doc.go say Direct and Upstreams.
- [x] R1.4 (torvalds S4; paranoid 4): `TestTheGuardIsTheIntersection`, a property over a table of tricky pairs (shrink, grow, partial overlap, to nothing, endpoints swapped, upstreams swapped, same): never wider than either side, no narrower than both, TUN/Mark held's. Done: `TestTheGuardIsTheIntersection` (11 pairs, also the other way round, an endpoint inside a dropped prefix, an upstream added, another TUN) through export_test's `GuardBetween`.
- [x] R1.5 (paranoid 1): a recovery test: a failed shrink, a failed grow, then a successful Apply; both `apply` and `reapplyGuard` give `GuardFor(new)`, and the guard widens back after a grow recovers. Mutant: `applied` set only on the first success. Done: `TestTheGuardFollowsTheRoutesBackAfterFailures`.
- [x] R1.6 (torvalds S5): assert the fallback step in the shrink test: after the failed fallback the guard is the endpoints alone. Done: the shrink test asserts the guard is `GuardFor(none)` after the failed fallback.
- [x] R1.7 (paranoid 2 = torvalds nit doc.go:249): forwarded IPv6 going direct is Linux's (the nftables guard hooks output only); macOS's pf probably refuses it too, unverified (TP-096). Scope it in RR14, doc.go and routing.md. Done: RR14 (and its tickets column names TP-096), doc.go and routing.md.
- [x] R1.8 (torvalds S8): RR14's "refused" holds only where the guard is enforced; cross-reference RR10–RR12. Done: RR14 says "where the leak guard is enforced (RR10–RR12 otherwise)".
- [x] R1.9 (torvalds S6; paranoid 5): `Status.GuardEnforced` says the guard for the last Want; it is the guard for the routes in place and the last Want. Done: torvalds' wording.
- [x] R1.10 (torvalds S7; go-style 8): the engine's shrink warning has the wrong IPv6 split; name forwarded IPv6 and the device's own where the guard isn't enforced. Done: "…still go direct over IPv4, for IPv6 forwarded on Linux, and for the device's own IPv6 where the leak guard isn't enforced".
- [x] R1.11 (go-style 2 = paranoid 5): doc.go "whose guard then holds" is wrong for a mixed change: the next step gives old ∩ new. Done: "which widens it to what the old and the new direct set both hold".
- [x] R1.12 (go-style 3): the `reapplyGuard` comment says "narrowed to the last Want's"; on a failed grow it is the routes in place's. Done: says the same rule as apply, cut to what the last Want's guard exempts too.
- [x] R1.13 (torvalds nit): the `applied` doc says "what the OS holds"; it is what the last successful Apply put in place. Done: "what the last successful Apply put in place".
- [x] R1.14 (torvalds nit = paranoid formatting = go-style 4): routetable.go:551's comment line is unwrapped (~110 columns). Done: the comment is rewritten and wrapped (`guardFor`'s doc).
- [x] R1.15 (go-style 6): the comment at guard_test.go:208-210 doesn't parse. Done: go-style's wording.
- [x] R1.16 (torvalds nit): `checkRoutesStayed` indexes `applies[n-1]` without checking n > 0. Done: n == 0 or a count mismatch fails without indexing.
- [x] R1.17 (torvalds nit): doc.go says nothing of the first failed Enforce applying no guard (`held == nil`); one sentence, so nobody "fixes" it into refusing all IPv6. Done: a doc.go paragraph (no guard until a Want's routes first go in, and why).
- [x] R1.18 (torvalds nit): the `|| Contains(dropped/added)` checks after `Equal` are redundant. Done: dropped.
- [x] R1.19 (go-style 7, optional): the shrink and grow tests could be one table test. Declined: the shrink test has the fallback step and a status check the grow test lacks, and the property test now carries the case table; go-style calls keeping them separate defensible.
- [x] R1.20 (go-style 9, pre-existing): `guardWarnRig` doesn't call `t.Helper()`. Done: `t.Helper()` added.
- Out of scope, pre-existing (paranoid): after a crash takeover, a first Apply that fails skips the guard (`held == nil`), so the crashed run's guard stays as it was, possibly wider than the new rules (RR14 at startup). Logged for the orchestrator; not fixed here.

## Log
- 2026-10-22 created in backlog (TP-077 review round 2)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Guard)
- 2026-10-28 backlog → in-progress, owner: agent-claude-tp127
- 2026-10-29 takeover (agent-claude-tp127b): WIP 0e0b488 re-read against the ticket; docs say forwarded IPv6 still follows the old routes (RR14 keeps D6 for it only), guardWhileFailing's doc scopes "never wider than the rules" to Direct
- 2026-10-29 tests: TestAFailedShrinkNarrowsTheGuard, TestAFailedGrowHoldsTheGuardToTheRoutes, and TestTheGuardIsPutBackWhileTheRoutesFail/TestEnforcerAppliesTheGuardWithTheRoutes updated (mixed change, fallback). Mutants, each killed: apply's failure branch holding the guard to the old routes (GuardFor(held): the shrink test and AppliesTheGuard fail); following the failed Want (GuardFor(w): the grow test fails); reapplyGuard ignoring failing (the shrink test after the guard's Watch, and PutBack, fail); guardWhileFailing without the intersection (w's Direct: PutBack and the grow test fail)
- 2026-10-29 make lint, make test green; make lab-test green on b0061e1 (lab 379.7 s, gotest ok in 36 packages). origin/rewrite merged after it (d29e45c: tickets only, no code change). Not verified: the pf adapter's reload on a narrowed Exempt on a real macOS (unit and lab tests use the fake guard and nftables)
- 2026-10-29 in-progress → review
- 2026-10-29 review → has-errors (round 1: torvalds, paranoid, go-style; R1.1–R1.20; cross-family review failed to connect, runs in round 2)
- 2026-10-29 has-errors → in-progress, owner: agent-claude-tp127
- 2026-10-29 round 1 fixes (R1.1–R1.20): one rule `guardFor(held, want)` in `apply` and `reapplyGuard`, no `failing` branch; Upstreams intersected; exported `lists.Set.Intersect` (the engine's shrink uses it); forwarded IPv6 scoped to Linux, macOS unverified (TP-096) in RR14, doc.go, routing.md; RR14 cross-references RR10–RR12; doc and comment fixes. Out of scope, logged only (paranoid, pre-existing): after a crash takeover a first Apply that fails applies no guard (`held == nil`), so the crashed run's guard stays as it was, possibly wider than the new rules
- 2026-10-29 mutants, each killed: `applied` set only on the first success (TestTheGuardFollowsTheRoutesBackAfterFailures, TestTheGuardFollowsTheDirectUpstreams); Upstreams taken from want (TestTheGuardIsTheIntersection); an exact-prefix intersection instead of an address one (TestTheGuardIsTheIntersection: partial overlap both ways, shrink, grow, to nothing, endpoint inside a dropped prefix; and the shrink, grow and recovery tests); `Intersect` as `s.Minus(t)` (TestIntersect); `reapplyGuard` holding to `GuardFor(held)` (the shrink test after the guard's Watch, PutBack); an endpoints-only Want keeping held's guard (the shrink test's fallback-step assertion, AppliesTheGuard, the property test); TUN taken from want (property test, "another TUN"); want's Direct with no intersection (property, grow, PutBack, recovery); `apply` applying `GuardFor(held)` (shrink, AppliesTheGuard) or `GuardFor(w)` (grow, recovery)
