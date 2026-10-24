---
id: TP-129
title: "macOS guard: a quick pass inside an anchor evaluated before the hook"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-126]
refs: []
owner: ""
branch: ""
---

## Goal
The macOS IPv6 guard reports itself not enforced while a `pass ... quick` that can match outgoing IPv6 sits inside an anchor pf's main ruleset evaluates before `anchor "com.apple/*"`, as it already does for a quick pass in the main ruleset itself.

## Scope
- Today `hooked()` reads only the main ruleset. Other VPN and firewall software adds its own anchors to pf (in `/etc/pf.conf` or loaded at run time), so a quick pass inside one of them, evaluated before the hook, lets IPv6 out around the guard. Health keeps saying the guard is enforced.
- Read the anchors the main ruleset references before the hook (`pfctl -a <name> -s rules`, recursing through nested anchors, bounded) and apply the same verdict as for a quick pass above the hook, using TP-126's `checkBypass`.
- Mind the poll's cost: TP-126 runs pfctl six times per poll. Read the earlier anchors only when the main ruleset has any anchor before the hook, and say what that costs.
- Fake-pfctl tests only (no real pfctl). The device check goes into TP-096 alongside TP-126's.

## Acceptance
- [ ] a fake-pfctl test: a quick pass inside an anchor the main ruleset evaluates before the hook makes the guard not enforced, and the anchor stays in place for the rest. Mutation: not reading the earlier anchor fails it
- [ ] a nested anchor, and an anchor after the hook (not a bypass), each have a test
- [ ] RESIDUAL-RISKS.md RR12 drops this case
- [ ] `make lint`, `make test` pass

## Notes
- From TP-126's round-2 design review (2026-10-22). Of TP-126's out-of-scope items, the orchestrator decided:
  - A mark-setting chain in another nftables table (Linux) is accepted. Setting a mark takes CAP_NET_ADMIN (root), as adding a chain does, and the guard compares the whole value (0x7470), which no other known software sets. The guard can only police its own table without owning the whole ruleset, and a root process that deliberately forges the mark has already won.
  - This macOS case gets a ticket, because ordinary third-party software does it.
- From TP-126's round-3 design review: `killedUnder` uses `checkBypass`'s error text as the bypass's identity. A failure to read pf counts as "the same bypass" and skips the kill. Two quick passes above the hook, or an earlier anchor's rules changing under one name, don't change the text. Since this ticket reworks the bypass check, key the kill on the findings (a list of bypasses plus an error for "couldn't read pf") instead of the text.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Guard lane: after TP-127, before TP-137 (the same two pf files).

## Log
- 2026-10-22 created in backlog (TP-126 review round 2)
- 2026-10-22 docs: the mark-chain reason corrected (the mark value is public); TP-126 round 3's bypass-identity note added
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Guard)
