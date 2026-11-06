---
id: TP-153
title: "netcfg (Linux): Watch sees a rule with our protocol added by someone else"
milestone: M2
area: dataplane/netcfg
repo: thinkpol-vpn
size: S
depends_on: [TP-135]
refs: []
owner: "agent-tp-153"
branch: "tp-153-netcfg-watch-sees-a-rule-added-beside-ours"
---

## Goal
A rule carrying our protocol that someone else adds beside ours (e.g. a blackhole next to rule 5300) brings an Apply, which removes it, instead of staying until some other event.

## Scope
- `relevant` (internal/dataplane/netcfg/watch_linux.go, TP-135's branch) counts RTM_DELRULE of our protocol, but ignores RTM_NEWRULE entirely. Since TP-135 an Apply removes such a twin (`TestApplyRemovesABlackholeBesideTheLookup`), but nothing triggers that Apply.
- Count an RTM_NEWRULE as relevant when it carries our protocol (`parseRawRule`, `c.proto`); an unreadable one counts, as for RTM_DELRULE.
- Our own adds raise RTM_NEWRULE too: say what that costs (one extra Apply after each Apply that adds rules, which finds nothing to do), or how it is avoided, and check it doesn't feed the TP-148 loop.
- A rule of another protocol stays irrelevant (rule churn by other software must not drive Applies).

## Out of scope
- Rules of another protocol ahead of ours: Survey's job, not Watch's.

## Acceptance
- [x] `TestRelevantRuleDeletes` (or a sibling) covers RTM_NEWRULE: ours relevant, another protocol's not, unreadable relevant; mutation: ignoring RTM_NEWRULE again fails it
- [x] a lab test: a blackhole with our protocol added beside our rule is gone after the next debounce without any other event
- [x] `relevant`'s comment and netcfg doc.go say which rule events count
- [x] `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` pass

## Notes
- Source: TP-135 round-3 correctness review, #3 (its Log's out-of-scope line).

## Log
- 2026-10-29 created in backlog (TP-135 round-3 review)
- 2026-10-31 backlog → in-progress, owner: agent-tp-153
- 2026-10-31 done: `relevant` (watch_linux.go) counts RTM_NEWRULE like RTM_DELRULE: our protocol or unreadable counts, another protocol's doesn't. Its comment and netcfg doc.go (Watching) say which rule events count
- 2026-10-31 own adds: a re-Apply that adds rules while the watch runs raises RTM_NEWRULE of ours, so one extra Apply follows that finds nothing to do and raises nothing (an Apply's own deletes did so already). Enforce's own Apply runs with the watch paused, so it adds none. No TP-148 loop: a failing Apply's undo already signalled via RTM_DELRULE, and the Enforcer holds events while failing until RetryAfter
- 2026-10-31 tests: `TestRelevantRuleDeletes` renamed `TestRelevantRuleEvents`, runs ours/another's/unreadable/too short for both RTM_NEWRULE and RTM_DELRULE; lab `TestWatchBringsTheApplyThatRemovesATwin` (blackhole with our protocol beside rule 5299 brings a signal; the Apply then leaves only the lookup) and a "rule of ours added" line in `TestWatchSeesGatewayChangesAndOwnRemovals`. Mutation `case unix.RTM_DELRULE:` (NEWRULE ignored again) fails TestRelevantRuleEvents (NEWRULE ours/unreadable/too short) and TestWatchBringsTheApplyThatRemovesATwin (no signal); restored
- 2026-10-31 not verified: the lab test drives Apply from the signal itself, not through the route-table Enforcer's debounce (routetable is off limits while TP-157 runs); an Enforcer-level check would be a line in routetable's TestEnforcesInANamespace
- 2026-10-31 make lint, make test, make lab-gotest PKG=./internal/dataplane/netcfg/... green; full make lab-test green on 77eaa97 (36 packages)
- 2026-10-31 in-progress → review
- 2026-10-31 review → done, merged into rewrite (round 1: go-paranoid merge, go-style merge; left for TP-157's round or a follow-up: routetable/doc.go:220-227 and routetable.go:264-268 still say the Enforcer re-applies only when its routes or rules are removed, now also when a rule with its protocol is added)
