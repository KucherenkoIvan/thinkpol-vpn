---
id: TP-126
title: "IPv6 guard: a dormant table or a foreign chain goes unrepaired"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-126"
branch: "tp-126-guard-blind-spots"
---

## Goal
A foreign change that turns the IPv6 leak guard off is repaired (or reported as not enforced), as DESIGN promises for the changes the guard already watches.

## Scope
- **Linux, proven in the lab (2026-10-22).**
  - **Dormant table.** `nft add table inet thinkpol-guard '{ flags dormant; }'` turns the guard off: the kernel unregisters a dormant table's base chains, and an IPv6 ping out the physical interface leaks. Nothing repairs it: `touchesGuard` (`firewall/guard_linux.go`) ignores `NFT_MSG_NEWTABLE`, and `whole()` doesn't look at the table's flags, so `Apply` returns early, even from the one-minute backstop, and `GuardEnforced` stays true.
  - **Foreign chain.** A base chain added to the guard's own table, such as a `pre` chain at output that sets the route mark, is never seen: `touchesGuard` ignores `NFT_MSG_NEWCHAIN`, and `whole()` checks only `output`. That one leaked too.
  - **Fix.** Watch `NEWTABLE` and `NEWCHAIN`. `whole()` requires table flags of 0 and exactly one chain, `output`. `Apply`'s rebuild already replaces the table.
- **Nit.** A policy change on `output` is caught only by the backstop, not by the watch. It fails closed. Watching `NEWCHAIN` fixes it too.
- **macOS, suspected from reading the code only. Check on paper and, if confirmed, add tests with the fake pfctl.**
  - `set skip on <physical interface>` disables pf filtering on that interface, and it doesn't show in `pfctl -s rules`. Nothing checks `pfctl -s Interfaces`.
  - `hooked()` scans only the main ruleset, so a `pass quick` in another `com.apple/*` anchor evaluated before the guard's anchor isn't seen.
- Fix the residual-risks row on foreign changes (TP-077's table: "repaired within about 1 s"), so it says what is and isn't repaired.

## Acceptance
- [x] lab tests: a dormant guard table, and a foreign base chain in the guard's table, are each repaired, and the leak test then blocks. Mutation: dropping either new check fails its test
- [x] macOS: each suspicion is confirmed with a fake-pfctl test and fixed, or shown not to apply, with the reason in the Log
- [x] `make lint`, `make test`, `make lab-test` pass

## Review findings
Round 1 (2026-10-22): correctness (merge), design (fix first), second opinion (merge). Linux is ready; the macOS half and the ticket need a short round.
- [x] R1.1 `guard_darwin.go` ~221-223: when `-s Anchors` answers "Invalid argument" or "not found", `checkBypass` returns nil, i.e. enforced: a failed check passes. It can't be needed (it runs only after a load into `com.apple/000.thinkpol`, so `com.apple` exists) and no fake reaches it. Return the error.
- [x] R1.2 Two functions now decide "pf evaluates the hook but something gets past it", at different times: `hookBypassed` (before the load: no anchor, no enable) and `checkBypass` (after, so the interfaces pf does filter stay guarded meanwhile, which applies to a quick pass above the hook just as well). Read the main ruleset once; `hookMissing` stays the early unsupported error; every not-enforced verdict (a quick pass above the hook, a skipped interface, an earlier anchor) moves into one check that runs last in `Apply` and in `broken()`. `TestAQuickPassAboveTheHookIsNotEnforced` then checks the anchor is whole after the failing Apply, as `TestASkippedInterfaceIsNotEnforced` does.
- [x] R1.3 `Apply`'s doc comment (~138-143) lists the old steps; add the check that now runs last.
- [x] R1.4 Fake consistency (`fakepf_darwin_test.go` ~85, ~267-277): the fake lists `200.AirDrop` and `250.ApplicationFirewall` under `-s Anchors` but doesn't hold them, so `-a com.apple/200.AirDrop -s rules` answers "Invalid argument" for an anchor it just listed. Seed them in `newFakePF` and have `-s Anchors` walk `f.anchors`. Say on `skip` that a name no interface has is listed too (unverified on Darwin).
- [x] R1.5 Tests: pin the deliberate strictness: `{"lo (skip)\n", []string{"lo"}}` in `TestSkipped` with a comment saying it's on purpose. The Linux test's `repaired("the chain's policy was changed")` can't see a repair (with `policy drop` the guard's rules decide every packet either way; dropping `whole()`'s policy check still passes): assert the rebuilt chain's policy is accept.
- [ ] R1.6 Docs and ticket, after TP-077 merges (it moves the guard's mechanism out of DESIGN.md into `firewall/doc.go` and the residuals into RESIDUAL-RISKS.md): merge rewrite, put this ticket's guard text in `firewall/doc.go` ("Linux: an nftables table", "macOS: polling", "What the macOS guard doesn't do"), not DESIGN.md; say there what the Linux guard still can't see (a base chain in *another* table that sets the links' mark before the guard's chain: the guard trusts the mark; only its own table is checked); narrow RR11 (and RR12's nested-anchor clause) in RESIDUAL-RISKS.md to what is left, with this ticket's checks. That replaces the Scope line on "the residual-risks row", which can't be done before TP-077. Move the Log's out-of-scope items (another table's mark chain; a quick pass inside an anchor the main ruleset evaluates before the hook; `set skip` on a non-interface name) into a `## Notes` "Out of scope" list.
- [x] R1.7 Device handoff: the parsers rest on pfctl's source and man page, not a Mac. Add a checklist item to TP-096 itself: run `pfctl -s Interfaces -v` and `pfctl -a com.apple -s Anchors` on a stock Mac and save both; the guard reports neither a skipped interface nor an anchor before `000.thinkpol`; with `set skip on lo` (no such interface), does "lo (skip)" appear.
- [x] R1.8 Nits: the lab-test Log line names 384ae04 while head was 1b68b77: say what changed after it, or re-run; `guard_darwin.go` ~23's "six pfctl runs" count: recount after R1.2; optional, from correctness: while a bypass condition persists, every failing Apply re-runs `killStates` every ~5 s (harmless with stateless rules, but it churns forever): skip the kill when the anchor didn't change, or say why not.

## Notes
- Found by TP-077's correctness review (2026-10-22) while checking the residual-risks table against the code, then proven by a throwaway lab test (`TestGuardDormantGap`, not committed). The lab table:
  - dormant: no signal, still dormant after a re-apply, leaks;
  - policy drop: no signal, repaired by the backstop, no leak;
  - an extra accepting base chain: no signal, stays, no leak;
  - add then delete a chain: signal, clean;
  - a mark-setting base chain in the guard's table: signal, stays, leaks.

## Log
- 2026-10-22 created in backlog (lab-confirmed gap from TP-077's review)
- 2026-10-22 backlog → in-progress — owner: agent-tp-126, branch: tp-126-guard-blind-spots
- 2026-10-22 Linux: `touchesGuard` watches NEWTABLE and NEWCHAIN; `whole()` wants the table's flags 0 and its only chain `output` (one dump of the inet chains). New lab test `TestIPv6GuardRepairsItsTableTurnedOff`: a dormant table, a foreign base chain setting the links' mark (each shown leaking first), and a policy set on `output` are each signalled and repaired, and a ping bound to eth0 is refused again. On the old code it fails (no signals, both leaks stay). Mutations, each run in the lab and each failing the test: NEWTABLE dropped (no signal for dormant), the flags check dropped (dormant still leaks after the re-apply), NEWCHAIN dropped (no signal for the chain or the policy), the one-chain check dropped (the mark chain still leaks). The rebuild of a dormant table (add, delete, add in one batch) works on the lab's kernel. DESIGN.md's Linux guard text says what the re-apply compares and what the watch sees
- 2026-10-22 macOS, both suspicions confirmed on paper (pfctl's source and man page; no real pfctl run). (1) `set skip on <iface>` is a pf option, not a rule: `pfctl -s rules` never lists it, and pf passes a skipped interface's packets before any rule, the anchor's included; only `pfctl -s Interfaces -v` shows it, as "<name> (skip)". (2) `anchor "com.apple/*"` evaluates the children in name order (pf keeps anchors sorted by path, strcmp), and a quick rule inside an anchor ends the whole evaluation; `hooked()` reads only the main ruleset, so a child named before `000.thinkpol` (`0.x`, `000`, `-x`) with a quick pass went unseen. Fix: `checkBypass` (guard_darwin.go), run last in Apply (so what pf does filter is guarded meanwhile) and in every poll, fails as not enforced (ordinary, retried) while pf skips anything but lo0 and the utun, or any anchor under com.apple sorts before ours (by existence, not content: one run, and nothing has reason to sort first). Polls now run pfctl six times. Fake pfctl: `-s Interfaces -v` and `-a com.apple -s Anchors`. Tests: `TestSkipped`, `TestAnchorsBefore`, `TestASkippedInterfaceIsNotEnforced`, `TestAnAnchorBeforeOursIsNotEnforced`, two new cases in `TestWatchSignalsWhenTheGuardBreaks`, two new keys in `TestPfctlFailuresAreRetried`. Mutations, each failing a test: the skip check off, the anchor-order check off, the poll without `checkBypass`, Apply without it, lo0 and the utun not exempt, the name order reversed. DESIGN.md's macOS guard text updated
- 2026-10-22 not verified: the exact output of `pfctl -s Interfaces -v` and `pfctl -a com.apple -s Anchors` on macOS (taken from pfctl's source: "<name> (skip)" lines, and "  com.apple/<name>" lines, a relative name also read). The device run (TP-096) should check both, and that a stock Mac reports neither a skipped interface nor an anchor before ours. The residual-risks row (RR13, TP-077's table) isn't on `rewrite` yet, so it isn't changed here; it should say that the Linux guard repairs a dormant table and foreign chains in its own table, and that macOS reports a skipped interface or an earlier anchor as not enforced
- 2026-10-22 `make lint` and `make test` pass; `make lab-test` passes on 384ae04 (LAB_P=4: 35 packages in lab nodes, and the lab/ suite)
- 2026-10-22 out of scope, for the orchestrator: (a) Linux: a base chain in *another* table that sets the links' mark before the guard's chain leaks the same way; the guard trusts the mark by design, so only its own table is checked here. (b) macOS: a quick pass in an anchor the main ruleset evaluates before the hook is still unseen (DESIGN names it); it could be reported the same way as an earlier com.apple anchor. (c) open question: a skip on a name that is no real interface (`set skip on lo`, a group) also reports not enforced; strict on purpose, a device run would show whether stock software does that
- 2026-10-22 in-progress → review
- 2026-10-22 review → has-errors (round 1: R1.1-R1.8)
- 2026-10-22 has-errors → in-progress — owner: agent-tp-126, round 1 findings
- 2026-10-22 R1.1: an `-s Anchors` failure is a failure ("Invalid argument" included); pinned in `TestAnAnchorBeforeOursIsNotEnforced`, mutation: swallowing "Invalid argument" again fails it
- 2026-10-22 R1.2/R1.3: `checkHook` reads the main ruleset once and fails only for a missing hook (unsupported, before the load); `checkBypass(main, tun)` holds every not-enforced verdict (a quick pass above the hook, a skipped interface, an earlier anchor) and runs last in Apply (after the enable) and in `broken()`. `TestAQuickPassAboveTheHookIsNotEnforced` now checks the anchor is whole after the failing Apply. Mutation: dropping the quick-pass verdict from `checkBypass` fails it, `TestStatesMadeWhileTheGuardFailedAreKilled` and the Watch test. Apply's and the type's doc comments, and DESIGN.md's macOS text, say so
- 2026-10-22 R1.4: the fake holds the stock Apple anchors it lists (seeded in `newFakePF`, `-s Anchors` walks `f.anchors`), checked by `TestTheFakeHoldsTheAnchorsItLists`; `skip` says a name no interface has is listed too (unverified on a Mac)
- 2026-10-22 R1.5: `TestSkipped` pins `lo (skip)` as reported, on purpose. The Linux test checks the rebuilt chain's policy is accept; lab run green, and dropping `whole()`'s policy check now fails it in the lab
- 2026-10-22 R1.7: TP-096 has an acceptance item for both pfctl listings on a stock Mac, with the guard applied, and `set skip on lo`
- 2026-10-22 R1.8: the earlier lab-test line: `make lab-test` ran on 384ae04; 1b68b77 only moved the ticket. The poll still runs pfctl six times (main ruleset, interfaces, anchors, the anchor's rules, its table, info), recounted. Kill churn: while one bypass lasts, states are killed once (`bypassKilled`), not on every retry, and again on the Apply after it ends or after a reload or a new enable; `TestASkippedInterfaceIsNotEnforced` checks three retries read no states and a state made meanwhile goes once the skip ends. Mutations: the churn guard off, and `bypassKilled` not reset when the bypass ends, each fail it
