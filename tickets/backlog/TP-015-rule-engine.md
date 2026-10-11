---
id: TP-015
title: "Routing rule engine"
milestone: M1
area: dataplane/router
repo: thinkpol-vpn
size: M
depends_on: [TP-008]
refs: [R2, R3, DESIGN#routing-rules-and-dns]
owner: ""
branch: ""
---

## Goal
Ordered routing rules decide per destination whether traffic goes direct, through a chain, or is blocked.

## Scope
- Rule model: ordered, first match wins; matchers `default`, `cidr`, `geoip`; domain matchers parsed and kept but reported as not enforced in route-table mode.
- Actions `direct`, `chain:<name>`, `block`; at M1 a chain is a single egress node.
- Space defaults from the map, per-device overrides from a local file; presets "everything" and "all but domestic".
- Compiled into a longest-prefix-match table (IPv4 + IPv6) for the router, and into the set of `direct` prefixes for route-table enforcement.

## Acceptance
- [ ] table-driven tests cover overlapping prefixes, IPv6, override precedence and presets

## Notes
**From TP-016 (lists), review decisions:**
- `geoip:<name>` resolves to the section `BlobRef` with kind geoip and that `Name`; the bytes come from TP-017's store (SHA-256 checked) and `lists.Decode` turns them into a `*lists.Set` (`Contains`, `Prefixes`).
- **First match wins needs set difference:** `(*lists.Set).Minus` exists (TP-016). Walk the rules in order with a `claimed` set: a rule's effective addresses are its set `Minus` claimed, then add them to claimed (`Builder.AddSet` + `Build`). The `direct` prefixes for route-table mode are the union of the direct rules' effective sets. Build `cidr` matchers with `lists.Builder` too, so they follow the same IPv4-mapped rule (an IPv6 entry overlapping `::ffff:0:0/96` is refused; lists never hold it, and `Contains` looks mapped addresses up as IPv4).
- **Local ranges are a built-in fixed list in code** (in `internal/lists`, e.g. `lists.Local()`, next to the other sets), never a downloaded list. Decided which go `direct` in "all but domestic", ahead of the `geoip:<domestic>` rule:
  - direct, IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (LANs), `169.254.0.0/16` (link-local), `224.0.0.0/4` (multicast: mDNS, SSDP), `255.255.255.255/32` (limited broadcast, DHCP);
  - direct, IPv6: `fe80::/10` (link-local), `fc00::/7` (ULA LANs), `ff00::/8` (multicast);
  - **not** direct: `100.64.0.0/10`. It is the overlay range: the space's own networks (its IPv4 network in `100.64.0.0/10`, its ULA /48 in `fd00::/8`) are overlay destinations, classified before any rule and routed into the TUN (in the route table the /48 beats `fc00::/7` by length). Other CGNAT addresses (an ISP's) aren't LAN and follow the rules; the physical gateway and entry endpoints get their own routes in TP-018 (a gateway inside `100.64.0.0/10` is reached by its more specific connected route);
  - not listed: `127.0.0.0/8` and `::1` (the OS handles loopback before any route we install), `0.0.0.0/8`, `240.0.0.0/4` and other reserved ranges (default handling is fine), `::ffff:0:0/96` (IPv4 is matched as IPv4).
  - Recommended for the "everything" preset too: LAN traffic can't usefully go through an exit, and keeping it local hides nothing from a censor.

- **From TP-022's review (whoever merges second wires this):** TP-022 owns the local rules *file and API*: `agent.LocalRulesFile` (`rules.local` in the state dir, written atomically only by the service through `Node.SetRulePreset`, read in `LoadState` with the trusted reader; a parse error fails `Prepare`, never reads as empty), `agent.LocalRules` (same text format as `rules.Local`), `agent.RulePresets` (`space`, `everything`, `all-but-domestic`), `agent.ErrUnknownPreset`, `agent.ErrPresetUnavailable`. Left to wire: replace `agent.ParseLocalRules`'s rule lines with `rules.Local.UnmarshalText` (so bad rules fail at load), set `Node.applyRules` to call `Engine.SetRules` on the running device's engine (through the runner, like connect requests) and map `rules.ErrPresetUnavailable` to `agent.ErrPresetUnavailable`; feed the stored `LocalRules` to the engine at every start; then `Status.RulesEnforced` turns true.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 notes from TP-016 review: set difference in `internal/lists`, the built-in local list and what goes direct in "all but domestic"
