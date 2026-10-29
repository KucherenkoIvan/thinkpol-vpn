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
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-077's round-2 design review (2026-10-22): the row had no ticket. It breaks D6 (a must), and the subset case allows a fail-closed fix.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Guard lane: after TP-138, before TP-129 (the same two pf files).
- **Decision (2026-10-28): while an Apply fails, the guard is the intersection.** Where: `routetable.Enforcer`, the one place that picks the guard's Exempt after a failed Apply (`apply`'s failure branch, and `reapplyGuard` for the guard's own repairs); `guardWhileFailing(held, w)` is `GuardFor(held)` with Direct cut to what `GuardFor(w)` exempts too. Never wider than the routes in place (held), nor than the rules (w). The cases: a failed shrink (w ⊂ held) gives w's guard, so IPv6 to the dropped prefixes is refused; a failed grow (held ⊂ w) keeps held's; a mixed change (some added, some dropped) exempts only the prefixes both keep: an added one has no route yet (into the TUN anyway), a dropped one is what the rules now tunnel (refused). Endpoints are part of GuardFor's Direct and intersect the same way. Upstreams, TUN and Mark stay held's (the routes in place). The engine's fallback to nothing direct, when it fails too, narrows the guard to the endpoints alone until the engine's next step (the new rules' Want) narrows it to old ∩ new; if the router change fails in between, the guard stays at the endpoints while the fallback is retried: fail closed, the fallback's own intent. The guard's adapters reload on any change of Exempt and the pf one kills states it no longer exempts, so no firewall change is needed. Forwarded IPv6 (containers, VMs) isn't the guard's: it follows the old routes' throws like IPv4, so RR14 keeps D6 for forwarded IPv6 only (2026-10-29, takeover).

## Log
- 2026-10-22 created in backlog (TP-077 review round 2)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Guard)
- 2026-10-28 backlog → in-progress, owner: agent-claude-tp127
- 2026-10-29 takeover (agent-claude-tp127b): WIP 0e0b488 re-read against the ticket; docs say forwarded IPv6 still follows the old routes (RR14 keeps D6 for it only), guardWhileFailing's doc scopes "never wider than the rules" to Direct
- 2026-10-29 tests: TestAFailedShrinkNarrowsTheGuard, TestAFailedGrowHoldsTheGuardToTheRoutes, and TestTheGuardIsPutBackWhileTheRoutesFail/TestEnforcerAppliesTheGuardWithTheRoutes updated (mixed change, fallback). Mutants, each killed: apply's failure branch holding the guard to the old routes (GuardFor(held): the shrink test and AppliesTheGuard fail); following the failed Want (GuardFor(w): the grow test fails); reapplyGuard ignoring failing (the shrink test after the guard's Watch, and PutBack, fail); guardWhileFailing without the intersection (w's Direct: PutBack and the grow test fail)
