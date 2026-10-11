---
id: TP-015
title: "Routing rule engine"
milestone: M1
area: dataplane/router
repo: thinkpol-vpn
size: M
depends_on: [TP-008]
refs: [R2, R3, DESIGN#routing-rules-and-dns]
owner: "agent-tp-015"
branch: "tp-015-rule-engine"
---

## Goal
Ordered routing rules decide per destination whether traffic goes direct, through a chain, or is blocked.

## Scope
- Rule model: ordered, first match wins; matchers `default`, `cidr`, `geoip`; domain matchers parsed and kept but reported as not enforced in route-table mode.
- Actions `direct`, `chain:<name>`, `block`; at M1 a chain is a single egress node.
- Space defaults from the map, per-device overrides from a local file; presets "everything" and "all but domestic".
- Compiled into a longest-prefix-match table (IPv4 + IPv6) for the router, and into the set of `direct` prefixes for route-table enforcement.

## Acceptance
- [x] table-driven tests cover overlapping prefixes, IPv6, override precedence and presets — `rules.TestCompile` (a wider prefix first shadows a narrower one, a narrower one first carves a hole, IPv6 and IPv4-mapped lookups, the overlay first, domain rules kept but not enforced, missing lists, unavailable chains, no default, no rules), `TestEffectiveOverridesAndPresets` (local rules ahead of the space's, a local default, both presets, presets with local rules on top, an unavailable preset falling back), `TestPresetRules`, `TestLocalFile`; the property test `TestCompileMatchesFirstMatch` (400 random rule lists of both families against a naive first-match evaluator at every prefix's edges ±1, and a longest-prefix match over `Routes()` against `Lookup`; mutation-checked: dropping the claimed set, the direct-after-unknown rule or the IPv4-mapped unmapping each fails it); engine tests `TestRulesRouteThroughTheChainsExit`, `TestRulesFollowListsAndLocalChoices`, `TestAnExitCannotSpeakForOtherPeers` (mutation-checked), `TestAChainWithoutItsExitBlocks`; netmap `TestParseRule`, `TestOnlySectionsWithRulesNeedTheNewReader`, `TestReadersKeepRulesTheyCannotEnforce` and 22 new builder cases

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

**Implemented (TP-015).**

*Rules in the map* (`internal/netmap/rule.go`, schema `Section` fields 11–13):
- `Section.Rules []Rule{Match{Kind, Prefix, Value}, Action{Kind, Chain}}`, `Section.Chains []Chain{Name, Exit NodeID}`, `Section.Presets RulePresets{Domestic, Chain}`. Matchers `default`, `local`, `cidr`, `geoip`, `domain`, `domain-suffix`, `geosite`; actions `direct`, `chain:<name>`, `block`. Text form `<match> -> <action>` (`→` accepted): `ParseRule`/`ParseMatch`/`ParseAction`, `Rule.String`, `Rule.Check` (the builder's rule), `CheckListName`, `CheckChainName` (`[a-z0-9][a-z0-9-]{0,31}`). Domains are lowercase ASCII (IDN as `xn--`), lowercased and trailing dot dropped by the parser.
- `local` is a matcher, not a list: `lists.Local()` holds exactly the ranges decided above (100.64.0.0/10 not among them). `lists.All()` is every address a list can hold (IPv6 minus `::ffff:0:0/96`).
- **Section reader 2**: `SectionReader = 2`; `Build` marks only sections with rules, chains or presets `min_reader = 2`, so M0 nodes keep reading every other section and refuse (rather than ignore) one with rules.
- **Reader** (`wellFormed`): kinds non-zero (unknown non-zero kinds are kept and reported as not enforced), a cidr value in canonical prefix form, chains named once, no chain exit zero or the node itself. **Builder** (`validate`): every rule passes `Check` (cidr masked, no IPv6 overlapping `::ffff:0:0/96`), refers to an existing chain and a named blob of its kind (geoip/geosite), the last rule is `default`; chain names valid, exits are peers, no two chains share an exit (DESIGN's rule, at the section level); presets' domestic is a named geoip blob and their chain exists; no two blobs of one kind share a name.

*Compilation* (`internal/dataplane/rules`):
- `Effective(spaceRules, presets, Local) ([]Entry, base Preset)`: the device's own rules first, then the base (`PresetSpace` = the map's rules; `PresetEverything` = `local -> direct`, `default -> chain:<c>`; `PresetAllButDomestic` adds `geoip:<domestic> -> direct` after `local`). A preset the map can't build falls back to the space's rules (`PresetUnavailable` in status). `Entry{Rule, Origin (local|space|preset), Index}`.
- `Compile(entries, Options{Overlay, GeoIP func(name) (*Set, bool), Chain func(name) bool}) *Table`: walks rules in order with a claimed set seeded with the overlay networks (`Minus`, then union), so the overlay is never in any route. Fail-closed semantics: domain/geosite rules match no address (`ReasonByName`); a rule whose addresses are unknown (list missing `ReasonNoList`, unknown or unusable matcher `ReasonUnknownMatch`) matches nothing and, unless its action is `direct`, turns off every later `direct` rule (`ReasonAfterUnknown`); an unknown action, or a chain `Options.Chain` refuses, blocks (`ReasonUnknownAction`, `ReasonNoChain`); unmatched destinations are blocked; an empty rule list sends everything direct (M0 maps without rules behave as before).
- **Table form:** a disjoint partition was 250k routes at RU scale (the complement of a country fragments ~10×), so `Routes()` is a longest-prefix table: per family one `/0` route for the action with the most prefixes, plus every other action's prefixes (pairwise disjoint, clear of the overlay). "All but domestic" with an RU-sized list: 22,398 routes (22,396 direct + 2 defaults), `BenchmarkCompileCountry` ~35 ms. `Lookup(addr)` (overlay → false; IPv4-mapped as IPv4), `Direct() *lists.Set` (the exact minimal direct set for route-table mode), `Skipped() []Skip{Origin, Index, Reason}`.
- Local file: `rules.Local{Preset, Rules}` with `MarshalText`/`UnmarshalText`: `#` comments, at most one `preset <space|everything|all-but-domestic>` line, one rule per line, ≤ 1024 rules, errors say `line N`.

*Engine and router:*
- `router.Route.Direct`: destinations the rules send around the tunnel; one that enters the TUN anyway is dropped and counted (`Counters.Direct`), never sent through an exit.
- `EngineConfig.Blobs func(netmap.BlobRef) ([]byte, bool)` (checked by size and SHA-256, decoded once per hash, cache pruned to the section's blobs; called under the engine lock) and `EngineConfig.Rules rules.Local`; `Engine.SetRules(rules.Local)` and `Engine.ReloadRules()` recompile and set the router table at once. Rules compile on every Apply that can run (before removals, so a dropped chain blocks before its device goes).
- Each chain whose exit is a usable peer gets a WireGuard device `exit-<node id>` (`Engine.layout`, the default `assign`); the exit's allowed IPs are every address outside the overlay networks plus the exit's own overlay addresses (IPv6 only while the overlay carries it), tighter than TP-008's note (`0.0.0.0/0` + `::/0`): an exit can't pass its packets off as another peer's (`TestAnExitCannotSpeakForOtherPeers`). Rule routes: chain → its exit's egress, block → nil, direct → `Direct`.
- `Status.Rules{Preset, PresetUnavailable, Direct4, Direct6, Skipped}`: numbers and fixed reasons only, nothing quoted from the rules (tested).

**For downstream tickets:**
- **TP-018 (route table):** install `e.ruleTable.Direct().Prefixes()` (minimal, IPv4 then IPv6) through the physical gateway, everything else into the TUN; hook the route update where `compileRules` runs (Apply, `SetRules`, `ReloadRules`), since a preset switch or a list arriving changes it without a map. `Router.Direct` should stay 0 while enforcement works: a good lab assertion. Coarsening stays shrink-only (`Minus` the original empty).
- **TP-020 (DNS):** the resolver evaluates the same effective list (`rules.Effective(s.Rules, s.Presets, local)`; the engine keeps the local choice) by name: `domain` exact, `domain-suffix` the name or under it, `geosite` needs a geosite blob format (none yet), `default`'s action for the rest; IP-only rules (`cidr`, `geoip`, `local`) can't decide a name. Compile skips name rules, so a `domain → direct` changes which upstream answers, not how the address is routed.
- **TP-022 (CLI):** the local file is `rules.Local`'s text form (path in the state dir is the agent's); `rules.ParsePreset` for `rules preset <name>`; `Engine.SetRules` applies at once and the agent should also persist the file; render rule text from the file and the map, since status gives only origin, index and reason.
- **TP-030 (chains):** the device side of single-exit chains is done (`netmap.Chain{Name, Exit}`, one device per exit, rules to its egress, two chains to one exit refused by `netmap.Build`). Left: chain definitions in the controller/spec (hops, hop groups, N9 checks) that produce `Chains` and `Peers[].Paths`, multi-relay routes, the lab test, and exit hop groups (a `Chain` has one exit).
- **TP-014 (egress):** the exit's router still drops a device's internet traffic as `NotLocal` (`TestRulesRouteThroughTheChainsExit` waits for exactly that); relax the check per egress on egress-allowed nodes.
- **TP-017 (blobs):** feed `EngineConfig.Blobs` from the store and call `Engine.ReloadRules()` when a blob the section names arrives.
- **TP-004 / lab tickets:** the dev spec has no rules, chains, presets or blob refs yet; whoever first needs them in the lab (TP-018/TP-023) adds them (rules as `netmap.ParseRule` text, chains naming an exit node, `.geoip` files → named `BlobRef`s).

## Log
- 2026-10-10 created in backlog
- 2026-10-10 notes from TP-016 review: set difference in `internal/lists`, the built-in local list and what goes direct in "all but domestic"
- 2026-10-12 backlog → in-progress — owner: agent-tp-015, branch: tp-015-rule-engine
- 2026-10-12 docs: DESIGN.md "Routing rules and DNS" (matchers incl. `local`, where rules and presets live, section reader 2, compilation and fail-closed semantics, a device per exit) and "Repository layout" (`dataplane/rules`; lists read by the rules)
- 2026-10-12 in-progress → review — acceptance checked; `make lint`, `make test` and `go test -race` on dataplane, rules, router and lists pass
