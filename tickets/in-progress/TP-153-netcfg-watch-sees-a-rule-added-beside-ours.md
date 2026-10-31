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
- [ ] `TestRelevantRuleDeletes` (or a sibling) covers RTM_NEWRULE: ours relevant, another protocol's not, unreadable relevant; mutation: ignoring RTM_NEWRULE again fails it
- [ ] a lab test: a blackhole with our protocol added beside our rule is gone after the next debounce without any other event
- [ ] `relevant`'s comment and netcfg doc.go say which rule events count
- [ ] `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` pass

## Notes
- Source: TP-135 round-3 correctness review, #3 (its Log's out-of-scope line).

## Log
- 2026-10-29 created in backlog (TP-135 round-3 review)
- 2026-10-31 backlog → in-progress, owner: agent-tp-153
