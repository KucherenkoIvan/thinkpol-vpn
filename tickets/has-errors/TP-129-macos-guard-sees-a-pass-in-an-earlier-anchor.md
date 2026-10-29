---
id: TP-129
title: "macOS guard: a quick pass inside an anchor evaluated before the hook"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-126]
refs: []
owner: "agent-claude-tp129"
branch: "tp-129-macos-guard-sees-a-pass-in-an-earlier-anchor"
---

## Goal
The macOS IPv6 guard reports itself not enforced while a `pass ... quick` that can match outgoing IPv6 sits inside an anchor pf's main ruleset evaluates before `anchor "com.apple/*"`, as it already does for a quick pass in the main ruleset itself.

## Scope
- Today `hooked()` reads only the main ruleset. Other VPN and firewall software adds its own anchors to pf (in `/etc/pf.conf` or loaded at run time), so a quick pass inside one of them, evaluated before the hook, lets IPv6 out around the guard. Health keeps saying the guard is enforced.
- Read the anchors the main ruleset references before the hook (`pfctl -a <name> -s rules`, recursing through nested anchors, bounded) and apply the same verdict as for a quick pass above the hook, using TP-126's `checkBypass`.
- Mind the poll's cost: TP-126 runs pfctl six times per poll. Read the earlier anchors only when the main ruleset has any anchor before the hook, and say what that costs.
- Fake-pfctl tests only (no real pfctl). The device check goes into TP-096 alongside TP-126's.

## Acceptance
- [x] a fake-pfctl test: a quick pass inside an anchor the main ruleset evaluates before the hook makes the guard not enforced, and the anchor stays in place for the rest. Mutation: not reading the earlier anchor fails it
- [x] a nested anchor, and an anchor after the hook (not a bypass), each have a test
- [x] RESIDUAL-RISKS.md RR12 drops this case
- [x] `make lint`, `make test` pass

## Notes
- From TP-126's round-2 design review (2026-10-22). Of TP-126's out-of-scope items, the orchestrator decided:
  - A mark-setting chain in another nftables table (Linux) is accepted. Setting a mark takes CAP_NET_ADMIN (root), as adding a chain does, and the guard compares the whole value (0x7470), which no other known software sets. The guard can only police its own table without owning the whole ruleset, and a root process that deliberately forges the mark has already won.
  - This macOS case gets a ticket, because ordinary third-party software does it.
- From TP-126's round-3 design review: `killedUnder` uses `checkBypass`'s error text as the bypass's identity. A failure to read pf counts as "the same bypass" and skips the kill. Two quick passes above the hook, or an earlier anchor's rules changing under one name, don't change the text. Since this ticket reworks the bypass check, key the kill on the findings (a list of bypasses plus an error for "couldn't read pf") instead of the text.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Guard lane: after TP-127, before TP-137 (the same two pf files).
- TP-138 review: DIOCGETRULESETS on a missing anchor needs its own exact absence check (not AnchorMissing); reuse rulesOf; the ALTQ filter is exact since TP-138.
- TP-138 round-2 design nits to fold in: anchorsBefore should use the shared lines() reader, not its own split; parseReferences should take the whole pfOutput, so the none-held rule lives in one place; rename flush's `what` field to `modifier`; use realistic table ioctls (DIOCRCLRTABLES, DIOCRGETADDRS) in the Tables test cases, and add the doubled-answer case to TestPfctlsNoAnswersAreExact; re-wrap doc.go 336–338 and 395–397.

## Review findings
Round 1 (2026-10-29): correctness (paranoid: fix first), design (torvalds: fix first), style (go-style: fix first), second opinion (Cursor: fix first). No blockers; the walk holds. Decisions by the orchestrator (2026-10-29).
- [ ] R1.1 (paranoid #1) An anchor name with `*` inside a path component (`vpn/a*`) makes pfctl read another anchor (`-a` strips a trailing `*`), so a pass is missed. Any `*` in a path component except a trailing `/*` wildcard is a name the guard can't read: a bypass. In resolveAnchor and childAnchors, with cases in TestResolveAnchor and TestChildAnchors.
- [ ] R1.2 (paranoid #2; torvalds nit on RR11) The kill identity is only `where: line` of each pass, so narrowing a bypass (the call gets `on en1`, `quick`, a protocol, a block above the pass) doesn't kill, against doc.go's "any change kills". Build it from everything read up to the hook: each walked ruleset's lines with the anchor-call chain and quick flag. Keep doc.go's claim true; RR11 says "sees the bypasses change" to match.
- [ ] R1.3 (paranoid #3) No test kills the `anchorWalkKey` without-quick mutant: an anchor called without quick, then with quick, holding a non-quick pass. Add it.
- [ ] R1.4 (torvalds 1 = Cursor 3) Two readers of `-a com.apple -s Anchors`: anchorsBefore accepts any line and takes the absence answer as "none". anchorsBefore goes through childAnchors; readBypass's comment ("no answer isn't 'none'") fixed.
- [ ] R1.5 (torvalds 2 = go-style 2 = Cursor 1 "not its rules") doc.go says an earlier com.apple anchor's "existence counts, not its rules" and elsewhere that its rules are read. Keep TP-126's decision: its existence is the bypass; its rules are read only for the kill identity; the doc says so in one place, and guard_darwin.go's comment agrees.
- [ ] R1.6 (torvalds 3) killedUnder uses nil for both "none" and "unknown", so an Apply failing for a non-bypass reason re-kills every retry (TP-137 adds one). killedUnder gets a `valid` flag, set false on reload/enable through one `statesStale()` helper.
- [ ] R1.7 (torvalds 4) Apply has three `errors.Join(..., oldRelease)` exits; use one `later []error` ending so TP-137 is a one-line change. Move the kill bookkeeping out of takeReference.
- [ ] R1.8 (torvalds 5) childAnchors rejects a child name with a space, anchorRule accepts one: allow spaces in child names.
- [ ] R1.9 (torvalds 6 = go-style 1 = Cursor 1) doc.go "three things still let IPv6 past the anchor" lists four: "four things".
- [ ] R1.10 (torvalds 7 = Cursor 6; paranoid accepted) InspectIPv6Guard's GuardCheck says "hooked" while health says not enforced for an earlier anchor's pass. Filed as TP-151: name it in the Log and doc.go's "not covered" text.
- [ ] R1.11 (go-style 4; paranoid accepted) RR12's `nat pass`/`binat pass` case has no reason or ticket. Filed as TP-152: name it in RR12's Ticket column and doc.go.
- [ ] R1.12 (Cursor 2) RR12 says only "a `pass quick` in an anchor it calls"; any pass inside a quick anchor counts too. Reword.
- [ ] R1.13 (Cursor 4) If a Mac lists a nested name rooted without `/`, the walk reads a missing anchor and finds nothing (fail open). A wildcard child the listing named that then reads as missing is a bypass, never empty. Named calls to a missing anchor are normal pf (an empty anchor): document that, with the TP-096 device check.
- [ ] R1.14 (paranoid nit = Cursor 5) reachesIPv6Out takes any `inet` field as IPv4-only, so `tag inet`/`label inet` hides a pass. Look for the family only in the fields before proto/from/to/all; cases for `tag inet` and `label`.
- [ ] R1.15 (go-style 3; torvalds nit) maxEarlierAnchors counts pfctl runs (listings too): rename maxEarlierReads, say "pfctl runs" in its comment, error text and doc; drop the "64 deep" remark.
- [ ] R1.16 (go-style 5) TestAQuickPassInANestedAnchorIsNotEnforced has enforced cases: rename after the behaviour.
- [ ] R1.17 (paranoid nit, torvalds nit, go-style nit) The poll-cost comment (guard_darwin.go ~22) leaves out wildcard listings; doc.go's polling section says the worst case (22 runs under g.mu, each bounded at 15 s).
- [ ] R1.18 (go-style nits) the guard comment's wrap (~39-43) and two overlong test comment lines; the garbled checkBypass phrase; `first` → `markRead`, `budget` → `spend`; fake `parent` → `hasChildren`; `wants` → `want`; `children refused` with DIOCGETRULESETS; the shadowed `c`; the "stock main ruleset" test comment; TestAChangeTheErrorDoesntShowStillKills renamed; "unexpected stderr%s".
- [ ] R1.19 (torvalds nits) `bypass.rule` → `at`; anchorWalk holds `pf pfctl`, rulesOf a function of pfctl; answerNoAnchors next to the other answers of absence; the anonymous-anchor claim marked "(unverified, TP-096)"; a note on hookBypassed that only inspect uses it.

## Log
- 2026-10-22 created in backlog (TP-126 review round 2)
- 2026-10-22 docs: the mark-chain reason corrected (the mark value is public); TP-126 round 3's bypass-identity note added
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Guard)
- 2026-10-28 docs: TP-138 round 1's note (DIOCGETRULESETS absence check, rulesOf, exact ALTQ filter)
- 2026-10-28 docs: TP-138 round 2's design nits
- 2026-10-29 backlog → in-progress, owner: agent-claude-tp129
- 2026-10-29 done: checkBypass (guard_darwin.go) walks the main ruleset down to the hook (anchorWalk): a pass that ends evaluation (endsEvaluation: quick, or any pass inside a quick anchor) there or in any anchor called there is a bypass, followed through `-a X -s rules`, a wildcard's children (`-a X -s Anchors`, childAnchors) and nested calls (resolveAnchor: relative, `../`, absolute `/`), inbound-only and inet-only calls skipped, a wildcard stopping at the guard's own anchor, each anchor read once, at most 16 (maxEarlierAnchors); an anchor it can't name, a refused or unreadable listing, or more than 16 leave the guard not enforced. Parsers in pfctl_darwin.go (isHook, reachesIPv6Out, endsEvaluation, anchorRule, resolveAnchor, answerNoAnchors, childAnchors), reusing readLines/lines/onlyLine/rulesOf/AnchorMissing; hooked shares endsEvaluation and isHook
- 2026-10-29 the state kill is keyed on the findings ([]bypass{why, rule}, with where pf holds each rule), not on the error text; a check that couldn't read pf finds none and kills. Anchors under com.apple before the guard's still count by name, and their rules are now walked too, only to tell one bypass from another (a stock Mac has none, so no extra run)
- 2026-10-29 cost: a poll stays at six pfctl runs on a stock main ruleset (TestAnAnchorAfterTheHookIsNoBypass asserts 6); one more per anchor read and per wildcard listing, up to 16, only when the main ruleset calls an anchor above the hook or com.apple has one before ours
- 2026-10-29 TP-138 round-2 nits folded in: anchorsBefore uses lines(); parseReferences(pfOutput) holds the none-held rule (quiet stderr) and references() just calls it; flush's field renamed `modifier`; TestAnotherInvalidArgumentIsNoEmptyAnchor's Tables case fails with DIOCRCLRTABLES/DIOCRGETADDRS; doubled-answer cases in TestPfctlsNoAnswersAreExact (and a stderr loop for the none-held answer); doc.go's References and absence paragraphs re-wrapped
- 2026-10-29 docs: firewall/doc.go (the bypass list, the kill's identity, the poll's cost, the absence answers, "doesn't do" now names `nat pass`/`binat pass` instead of TP-129); RR12 rewritten (the earlier-anchor case moved from unseen to reported; `nat pass` added as the unseen case); TP-096 gets a device item for this (nested names as listed, the missing-anchor answer of `-s Anchors`, health)
- 2026-10-29 assumed, unrecorded (TP-096 item): pfctl prints nested anchor names relative to the anchor holding the rule (`../`) or absolute with a leading `/`, `/*` for a wildcard (OpenBSD's pf_anchor_copyout, which XNU's pf_ruleset.c carries); an anonymous anchor is listed as `anchor` without a name; `-a X -s Anchors` of a missing anchor prints exactly `Anchor 'X' not found.` on stderr and exits 0 (pfctl_show_anchors; the guard takes that line whatever the exit status); `-s Anchors` without -v lists direct children only. The fake follows these; the only recorded listing used is recorded-anchors-stock.txt (TestChildAnchorsReadsTheRecordedListing)
- 2026-10-29 mutation checks (each run, each failed its test): M1 call returns at once (not reading the earlier anchor) → TestAQuickPassInAnEarlierAnchorIsNotEnforced; M2 a wildcard read as a plain anchor, M3 nested names not relative to their anchor, M17 an inbound/inet anchor call followed, M18 no dedupe (a loop) → TestAQuickPassInANestedAnchorIsNotEnforced; M4 a quick anchor's quick not passed down, M5 endsEvaluation ignoring inQuick → TestAnyPassInAQuickAnchorIsNotEnforced (M5 also TestEndsEvaluation); M6 main read past the hook → TestAnAnchorAfterTheHookIsNoBypass; M7 a wildcard going on past the guard's anchor → TestAnEarlierCallOfTheGuardsAnchorStopsThere; M8 an anchor it can't name ignored, M9 no bound on anchors read, M20 `../` above the main ruleset allowed → TestAnEarlierAnchorTheGuardCantReadIsNotEnforced (M20 also TestResolveAnchor); M10 bypass identity without the rule, M11b kill skipped on a read failure, M12 com.apple earlier anchors' rules not read → TestAChangeTheErrorDoesntShowStillKills; M13 any stderr with nothing listed taken as no anchor, M14 the absence answer only with exit 0, M15 a listed line not checked as the path's child, M16 stderr ignored on a successful -s Anchors → TestChildAnchors; M19 an unclosed quoted name read as a name → TestAnchorRule; M21 the none-held References answer with any stderr → TestPfctlsNoAnswersAreExact and TestNoReferencesWithAWarningIsUnread; M23 onlyLine taking a doubled answer → TestPfctlsNoAnswersAreExact. Survived: M22 anchorsBefore back on strings.Split (an equivalent refactor: ALTQ chatter sorts after the guard's either way)
- 2026-10-29 not covered: InspectIPv6Guard's snapshot doesn't show what the anchors above the hook hold (GuardCheck stays hooked's verdict; it needs a localapi proto field), only their lines in MainRules; `nat pass`/`binat pass` aren't read (now in RR12 and doc.go)
- 2026-10-29 make lint, make test green; make lab-test (LAB_P=1, other labs up) green on 19f3711: Linux only, so it runs the firewall package's Linux tests and the rest of the lab; none of this ticket's darwin code or tests run there
- 2026-10-29 in-progress → review
- 2026-10-29 review → has-errors (round 1: paranoid, torvalds, go-style, Cursor; findings R1.1–R1.19)
