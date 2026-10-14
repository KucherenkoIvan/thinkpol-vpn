---
id: TP-021
title: "IPv6 leak prevention"
milestone: M1
area: dataplane
repo: thinkpol-vpn
size: M
depends_on: [TP-018, TP-019]
refs: [D6, DESIGN#ipv6]
needs_human: macos
owner: "agent-tp-021"
branch: "tp-021-ipv6-leaks"
---

## Goal
While connected, IPv6 goes through the tunnel or is blocked; it never leaks around it.

## Scope
- If the egress supports IPv6: route IPv6 into the tunnel like IPv4.
- Otherwise: block IPv6 on physical interfaces while connected (Linux nftables, macOS pf anchor), except to entry endpoints.
- Restore on disconnect, also after a crash (next start cleans up).

## Acceptance
- [x] lab capture (Linux): no IPv6 packet leaves a physical interface outside the tunnel while connected — `lab/ipv6leak_test.go` `TestNoIPv6LeavesAroundTheTunnel`: device-a connected with "all but domestic" (`lab/maps/routetable.yaml`); `ping -6 -I eth0`, `ping -6 -I <eth0's address>`, unbound `ping -6` and `curl -6 --interface eth0` to a foreign IPv6 site; a capture of the device's own outgoing IPv6 on every lab interface shows only direct destinations (the domestic site, `local`: the lab's unique-local networks, link-local, multicast) and the entry's endpoint, and does show the direct ping (the capture works). The same with the overlay IPv4-only (`-link-mtu 1300`) and after a kill -9 while connected; `-connect=false` removes the guard, a clean stop too. Deleted from outside while connected (`nft delete table`), the guard is back within about a second and the capture stays clean. Negative control, in the test: disconnected (no guard), the same bound ping is answered and the capture shows ICMPv6 and TCP from the device's address to the foreign site.
- [ ] the macOS checklist (pf anchor): round 2, after TP-019 merges (see Notes)

## Notes
- **From TP-014 (egress):** an exit whose uplink has no IPv6 (no IPv6 default route, or only unique local addresses) refuses a device's IPv6 inside its namespace with ICMPv6 "no route", at once, and none leaves; the device must still keep IPv6 from going around the tunnel itself.

- **From TP-057 (route table):** sockets bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, an `IP_PKTINFO` ifindex: `ping -I eth0`, NetworkManager's connectivity checks, systemd-resolved's per-link DNS) can't be confined by routing: IPv4 and IPv6 both leave by main's default route (the rule `oif <link> lookup main suppress_prefixlength 0` at 5298 exists so the kernel can resolve gateways, and IPv4 would otherwise reach on-link hosts by ARP anyway). Block them in the firewall while connected (e.g. nftables: output on a physical interface, not marked 0x7470, not to a direct destination, not to the LAN), at least for IPv6 here. `internal/dataplane/routetable` `TestGatewaysOnLinksAndBoundSockets` documents today's behaviour (`ip route get … oif eth0`): flip its assertions when the firewall lands.

Evidence: see Log (round 1, round 2).

**Round 1 (2026-10-14): Linux; round 2: the review's findings.** macOS waits for TP-019 (in review on its own branch, which also changes `routetable`); no darwin code here but a marked stub in the agent.

*What "route IPv6 into the tunnel when the egress has it, block it otherwise" came to.* Routing already did the first half: the route table sends IPv6 into the TUN whenever the overlay carries IPv6 (`Want.IPv6`), and an exit without an IPv6 uplink refuses it there at once (TP-014); with the overlay IPv4-only, IPv6 meets table 0x7470's unreachable default but for direct destinations and endpoints (TP-018, TP-057). A device can't tell from its map whether its chain's exit has IPv6, and needn't: either way nothing goes around. What leaked was locally generated traffic routing can't see: sockets bound to an interface (rule 5298 routes them by main's default route), other software's routes or tables ahead of ours. The guard closes that for IPv6, whatever the egress. Forwarded traffic is never bound to an interface, and rule 5301 keeps it in the tunnel: the guard doesn't look at it.

*Design* (DESIGN.md "Routing rules and DNS", route table on Linux; "IPv6"; "Repository layout", engine and agent):
- **Port in `routetable`** (`guard.go`, pure, builds for Android, never imports `firewall`): `Guard{Apply(ctx, Exempt), Watch(ctx), Close()}`, `Exempt{TUN, Mark, Direct, Upstreams}` with `Ranges6` and `LinkScoped`, `GuardFor(Want)` = exactly the table's throws (`Direct` ∪ `Bypass`) and the mark, `ErrGuardUnsupported`.
- **Adapter in `firewall`** (`guard_linux.go`, desktop-only, imports `routetable`): `IPv6Guard`, one nftables table owned by its name:
```
table inet thinkpol-guard {
  set exempt6 { type ipv6_addr; flags interval; elements = Direct's IPv6 ∪ fe80::/10 ∪ ff02::/16, merged }
  chain output { type filter hook output priority 2147483647; policy accept;   # after every other output chain
    oifname "lo" accept; oifname <TUN> accept
    meta nfproto != ipv6 accept                      # IPv4 is TP-048's
    meta mark 0x7470 accept                          # links, the direct DNS upstream (Upstreams: pf's)
    ip6 daddr @exempt6 accept
    icmpv6 type 133-137 ip6 hoplimit 255 accept      # neighbour discovery, whatever the target
    icmpv6 type 130-132 ip6 hoplimit 1 accept; icmpv6 type 143 ip6 hoplimit 1 accept   # MLD
    meta l4proto tcp counter reject with tcp reset
    counter reject with icmpx admin-prohibited }
}
```
  Refused, not dropped: TCP connect fails at once with ECONNREFUSED (a drop leaves it retrying SYNs), ICMP and UDP get the ICMPv6 error. Hooked at NF_IP6_PRI_LAST: a route chain that re-marks or reroutes does so before the guard looks. Applied in one transaction (add, delete, add the table: never a moment without it); re-applying what is in place only checks the chain, its rule count and the set are there (elements deleted one by one go unnoticed: only refusals could come of it). `Watch` reads nftables' own events (NFNLGRP_NFTABLES): a deletion in the table (table, chain, rule, set) or a rule added to it, or an overflowed socket, signals. A kernel without nf_tables (EPROTONOSUPPORT, EOPNOTSUPP, EAFNOSUPPORT) is `ErrGuardUnsupported`; `Close` removes the table and can be retried after a failure (on such a kernel there is nothing to remove).
- **Enforcer** (`routetable.go`): the guard follows routes that went in on every Apply and re-apply, with a status of its own (`Status.GuardEnforced`, `GuardError` = `ErrorGuard` "applying the leak guard failed", retried every `RetryAfter`, or `ErrorGuardUnsupported`, terminal); its failure never fails `Enforce` or the routes. The guard's `Watch` re-applies the guard alone, after a 200 ms debounce. `Close` and `Clear(g)` remove the guard before netcfg lets go of the owner lock; `Clear` clears the guard even when netcfg can't take the lock at all (`ErrUnsupported`), but not while another configurator holds it (`ErrBusy`: its guard is live). `New(g, log)`, `OpenWithGuard`; `Open` is routes-only.
- **Agent** (`leakguard.go`, `leakguard_linux.go`, `leakguard_other.go`): composes `routetable.New(guard, log)` with `firewall.NewIPv6Guard()` wrapped in `leakGuard`, which adds the resolver's direct upstreams to every Exempt (and signals their changes on Watch); `clearHostRoutes` = `routetable.Clear(newHostGuard())` for a disconnected or failed start. Health: `ipv6_guard_not_enforced` and `ipv6_guard_unsupported` (degraded). **Decision (orchestrator):** without nf_tables a device connects; health warns `ipv6_guard_unsupported` so the CLI and tray can say IPv6 from interface-bound apps isn't confined; not fail-closed.
- `lists.Set.Ranges`: the merged spans (disjoint, never adjacent), what an interval set wants.
- Ordering with the engine: shrinking takes routes out first, then the guard; growing puts routes first, so a new direct destination is refused for the moment between, never leaked. If the guard fails while shrinking, bound sockets may still reach the destinations just dropped from direct until the retry (status says so).
- Crash: the table stays with the route table (fail-closed for IPv6, bound sockets included) until the next start; a clean stop or disconnect removes it.

*Gotchas* (also in recall): google/nftables puts a message's set elements in one netlink attribute, whose length is 16 bits: over 64 KiB the kernel answers ENOENT, so elements go 1024 per message (`elementsPerMessage`). `Flush` sends the whole batch in one sendmsg: a country-sized set (~10k IPv6 ranges, 20k elements, ~700 KB) needs SO_SNDBUFFORCE/SO_RCVBUFFORCE (8 MiB, `sockbuf`), or the send fails and error acks overflow (ENOBUFS). An interval reaching the top address (ff00::/8) has no end element. iputils `ping -m` wants a decimal mark. In nftables events (NFNLGRP_NFTABLES) attribute 1 is the table's name for tables, chains, rules and sets. An nft counter observing a veth's far side counts the kernel's own neighbour solicitations too: match the crafted packet's destination.

*Cost:* 10,090 IPv6 ranges in 36–58 ms (namespace test); the RU-sized `TestCountrySizedTable`, with the guard: connect 0.31–0.33 s, one endpoint moved 0.13–0.14 s, to "everything" 0.25–0.29 s, back 0.26–0.29 s, disconnect 0.25 s (a shared Docker host).

*Effects worth knowing:* every interface but the TUN and lo counts as physical (rule 5298's set): IPv6 from a bound socket to another VPN's interface, a bridge or a veth is refused unless direct. NetworkManager's per-device IPv6 connectivity check and systemd-resolved's per-link IPv6 DNS fail while connected (that is the point; resolved's per-link domains already make `dns_not_protected`).

**macOS (round 2 of the platform work, after TP-019 merges): what it needs.**
1. `internal/dataplane/firewall/guard_darwin.go`: a pf guard implementing `routetable.Guard` (`Apply(ctx, Exempt)`, `Watch`, `Close`), as an anchor under Apple's `com.apple/*` hook (`com.apple/thinkpol`, loaded with `pfctl -a com.apple/thinkpol -f -`, so `/etc/pf.conf` is never edited). **First verify the main ruleset references `anchor "com.apple/*"`** (`pfctl -s rules` / `-s Anchors`) **or fail** with `ErrGuardUnsupported`-like status: an anchor nothing evaluates guards nothing. A persistent table holds the exempt destinations (pf tables take prefixes: `Exempt.Direct`'s IPv6 `Prefixes()`, `Exempt.Upstreams`, plus `routetable.LinkScoped`; `pfctl -a … -t thinkpol_exempt6 -T replace -f -`):
```
pass out quick on lo0 all
pass out quick on <utunN> all
pass out quick inet6 to <thinkpol_exempt6>
pass out quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136, 137 }   # with hop limit 255 if pf can say it, else noted
pass out quick inet6 proto icmp6 icmp6-type { 130, 131, 132, 143 }
block return out quick inet6 all
```
   pf must be enabled by reference (`pfctl -E` returns a token; `pfctl -X <token>` releases it), so the guard doesn't turn off a pf someone else enabled, nor leave pf on when it is gone.
2. **No socket mark on macOS:** links and the direct DNS upstream are bound to the physical interface (`IP_BOUND_IF`, TP-019's `ifbind`), not marked. Endpoints are in `Exempt.Direct`; the direct upstreams come in `Exempt.Upstreams`, which the agent already fills from its resolver (`agent.leakGuard`, round 2 of this ticket) and re-applies when they change.
3. **Records, crash, Clear:** the anchor and the pf token survive a crash (fail-closed, as on Linux). The firewall keeps its own record, `<statedir>/pf-guard.token`, with a boot-session header (as TP-019's records have, but its own file: using TP-019's netcfg records from `firewall` would make an import cycle); a fresh guard's `Close` (what `routetable.Clear` calls) flushes the anchor (`pfctl -a com.apple/thinkpol -F all`) and releases a token from the same boot; after a reboot the anchor is gone anyway and the record is dropped.
4. `agent/leakguard_darwin.go`: `newHostGuard` returning the pf guard (and narrow `leakguard_other.go`'s build line to `(!linux && !darwin) || android`). With TP-019's split routes, the guard also covers what its Notes leave to pf: foreign host routes over tunneled destinations (IPv6), scoped routing by source address, interface-bound sockets. `Watch`: pf has no event stream; poll the anchor's rule count (or rely on the backstop) and say so.
5. A darwin unit test for the generated anchor and table text (no pfctl), and **the checklist** on a real Mac, connected with "all but domestic": `ping6 -c1 -I en0 2001:4860:4860::8888` and `curl -6 -m5 --interface en0 https://[2001:4860:4860::8888]/` refused at once; `sudo tcpdump -ni en0 'ip6 and not net fe80::/10 and not net ff00::/8'` shows only direct destinations, entries and the direct upstream while browsing; `sudo pfctl -a com.apple/thinkpol -sr` lists the rules; after `sudo pkill -9 -f 'thinkpol up'` the same pings stay refused; `thinkpol up -connect=false` (then stop) leaves the anchor empty and pf's enable count as before (`sudo pfctl -s info`).

## Review findings
Round 1 reviews (design and correctness), orchestrator's list; nothing blocking, all fixed before merge.

- [x] 1 Watch the guard: subscribe to nftables table/chain deletions (NFNLGRP_NFTABLES) and re-apply through the Enforcer, so `flush ruleset` or `systemctl reload nftables` gets the guard back within about a second, not the 60 s backstop. Test: delete the table from outside, it comes back without an Apply.
- [x] 2 Adapter composition in the agent (DESIGN.md "Repository layout"): no `routetable/guard_linux.go`/`guard_other.go`; the agent builds `routetable.OpenWithGuard(c, firewall.NewIPv6Guard(), log)` and clears with `errors.Join(routetable.Clear(), firewall.ClearIPv6Guard())`; `routetable.Clear` clears routes only. The Guard port and GuardFor stay in routetable.
- [x] 3 Android boundary (option b): `Exempt` and `LinkScoped` move to routetable, which never imports firewall; firewall may import routetable. firewall/doc.go, AGENTS.md rule 4 and DESIGN.md's Android line stay true.
- [x] 4 Lock ordering: Close and Clear remove the guard before letting go of netcfg's owner lock; clearing the guard doesn't depend on `netcfg.New` succeeding; errors joined.
- [x] 5 `IPv6Guard.Close` retryable: closed only once the table is removed.
- [x] 6 The guard's own status: `Status.GuardEnforced` and a health code of its own; EOPNOTSUPP/EPROTONOSUPPORT or no nf_tables → terminal `ErrorGuardUnsupported` (no 5 s retries). Decision (orchestrator): without nf_tables connect proceeds and health warns loudly `ipv6_guard_unsupported` (not fail-closed); in DESIGN.md. ErrorGuard's text: "applying the leak guard failed".
- [x] 7 ND requires `ip6 hoplimit 255` (types 133–137), MLD `ip6 hoplimit 1` (130–132, 143); fix the comment.
- [x] 8 Honest apply-failure docs: Enforce's comment and the engine's log don't claim all-or-nothing when routes went in and the guard failed.
- [x] 9 Negative control in the lab test (a capture with the guard off shows ICMPv6 and TCP to the foreign site), or correct the ticket.
- [x] 10 TP-048 Notes: the kill switch is its own owner (`inet thinkpol-killswitch`, its own exempt4/exempt6, applied by the agent from the toggle and preset, survives disconnect), sharing only Exempt's shape; the IPv6 guard stays the route table's and lives and dies with the connection.
- [x] 11 macOS round 2 prep: `Exempt.Upstreams []netip.Addr` (pf has no mark), sourced by the agent; the plan uses the firewall's own `<statedir>/pf-guard.token` with a boot-session header (not TP-019's route records: an import cycle); verify the main ruleset has `anchor "com.apple/*"` or fail.
- [x] 12 Forwarded traffic: narrow the claim to locally generated traffic (rule 5301 confines forwarded traffic); consider a late output priority so a route chain re-marking after us can't slip through (do it if cheap, else note).
- [x] Nits: `sndbuf` → `sockbuf`; `whole()` counts without a fake set; `Status.Error`'s doc lists every `Error*`.

Resolution (round 2):
1. `IPv6Guard.Watch` (`firewall/guard_linux.go:263`, `touchesGuard` :318) reads NFNLGRP_NFTABLES: deletions in the guard's table, a rule added to it, or an overflow signal; the Enforcer subscribes to it beside netcfg's Watch (`routetable.go:550`) and re-applies the guard alone after a 200 ms debounce (`reapplyGuard` :656). Tests: `TestTheGuardComesBackOnItsOwn` (routetable namespace: `nft delete table`, `flush ruleset`, `delete chain`, each back within 3 s without an Enforce), firewall `TestIPv6GuardRefusesWhatRoutingCantConfine` (Watch signals a deletion, a flush and an inserted rule; not another table's changes), lab (deleted while connected: back within about a second, capture clean).
2. No `routetable/guard_{linux,other}.go`. The agent composes: `newHostGuard` (`agent/leakguard_linux.go:11`, `leakguard_other.go:12`: none, the marked macOS TODO), `routetable.New(guard, log)` (`routetable.go:347`) from `agent/dataplane.go:274`, `clearHostRoutes` = `routetable.Clear(newHostGuard())` (`agent/dataplane.go:215`, also `node.go`'s host clear). Deviation from the suggested `errors.Join(routetable.Clear(), firewall.ClearIPv6Guard())`: that would clear the guard after netcfg let go of the lock, against finding 4; `Clear(g)` takes the guard and closes it inside (`ClearIPv6Guard` is gone: a fresh guard's Close is the clear).
3. `Exempt`, `LinkScoped`, `ErrGuardUnsupported` and the `Guard` port live in `routetable/guard.go:19-98`; `go list -deps ./internal/dataplane/routetable` has no `firewall`; `firewall` imports `routetable` (`firewall/doc.go`). AGENTS.md rule 4 and DESIGN.md's Android line hold unchanged (firewall stays desktop-only; routetable builds for Android).
4. `Enforcer.Close` (`routetable.go:516`) and `Clear` (:362) close the guard before netcfg's Close releases the owner lock; `Clear` clears the guard even when `netcfg.New` fails, except with `netcfg.ErrBusy` (another configurator's guard is live); errors joined. Test: `TestEnforcerAppliesTheGuardWithTheRoutes` checks the order (guard, then routes).
5. `IPv6Guard.Close` (`firewall/guard_linux.go:227`) sets `closed` (and closes the namespace fd) only after the table is removed; a kernel without nf_tables has nothing to remove.
6. `Status.GuardEnforced`/`GuardError` (`routetable.go:282`), `dataplane.RouteTableStatus` likewise (`dataplane/routetable.go:36`), health `ipv6_guard_not_enforced`/`ipv6_guard_unsupported` (`agent/status.go:268,272`, degraded). `unsupported` (`firewall/guard_linux.go:138`) maps EPROTONOSUPPORT, EOPNOTSUPP, EAFNOSUPPORT to `ErrGuardUnsupported`: terminal (`applyGuard` :477), no retries. `ErrorGuard` = "applying the leak guard failed" (:310). DESIGN.md "Routing rules and DNS" records the decision. Tests: `TestEnforcerStopsTheGuardWhenUnsupported`, `TestHealth` cases.
7. ND only with `ip6 hoplimit 255` (types 133–137), MLD only with `ip6 hoplimit 1` (130–132, 143) (`guardRules` :356, `hopLimit` :416, comment :47). Test: `TestIPv6GuardPassesNeighbourDiscoveryOnlyOnTheLink` (an observer on the gateway counts a crafted NS to a global address with hop limit 64: 0, with 255: 1; MLD with 64: 0, with 1: 1).
8. The guard's failure no longer fails `Enforce` (it has its own status), so `Enforce`'s "all or nothing" is about the routes and says so (`routetable.go:395`), and the engine's shrink/grow logs (`dataplane/routetable.go`) only ever see route failures, which they describe correctly.
9. The lab test now captures the negative control itself (`lab/ipv6leak_test.go:194`): disconnected, the same bound ping and curl leave and the capture shows ICMPv6 and TCP from the device's address to the foreign site; the test fails otherwise.
10. TP-048's Notes rewritten: its own owner and table `inet thinkpol-killswitch` with `exempt4`/`exempt6`, applied by the agent from the toggle and preset, surviving disconnect; shares only Exempt's shape; the guard is the route table's and lives and dies with the connection.
11. `Exempt.Upstreams` (`routetable/guard.go:59`), filled by the agent's `leakGuard` from the resolver's direct upstreams (`agent/resolver.go:44,112`; their changes signalled on Watch so the Enforcer re-applies); Linux leaves them to the mark. The macOS plan in Notes uses `<statedir>/pf-guard.token` with a boot-session header and checks the main ruleset for `anchor "com.apple/*"` or fails.
12. Exempt's doc (`routetable/guard.go:36-43`), DESIGN.md and Notes now say locally generated traffic, and that rule 5301 confines forwarded traffic. Cheap, so done: the chain hooks at NF_IP6_PRI_LAST (`guardPriority`, `firewall/guard_linux.go:33`), after every other output chain.
- Nits: `sockbuf` (:97); `whole()` (:211) counts `guardRules(e, guardSet, 0)` without a set; `Status.Error`'s and `GuardError`'s docs list every `Error*`.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
- 2026-10-12 docs (TP-057 review): interface-bound sockets are the firewall's to confine
- 2026-10-14 backlog → in-progress — owner: agent-tp-021, branch: tp-021-ipv6-leaks (round 1: Linux; the orchestrator starts it while TP-019 is in review, macOS pf waits for its merge)
- 2026-10-14 Linux: `firewall.IPv6Guard` (nftables `inet thinkpol-guard`), applied with the route table (`routetable.Guard`, `GuardFor`, `OpenWithGuard`), `lists.Set.Ranges`; `TestGatewaysOnLinksAndBoundSockets` flipped for IPv6; lab `TestNoIPv6LeavesAroundTheTunnel`; DESIGN.md "Routing rules and DNS", "IPv6", "Repository layout"; TP-048 Notes; acceptance split into the lab capture (checked) and the macOS checklist (round 2)
- 2026-10-14 in-progress → review — round 1: Linux; macOS pf pending TP-019. `make lint`, `make test`, race on touched packages and `make lab-test LAB_P=2` pass; the macOS checklist box stays open until round 2
- 2026-10-14 review → has-errors — design and correctness reviews: findings 1–12 and nits (see Review findings)
- 2026-10-14 has-errors → in-progress — owner: agent-tp-021, round 2: the review findings
- 2026-10-14 round 2: review findings 1–12 and nits fixed (see Review findings); merged origin/rewrite (TP-067 board docs); DESIGN.md "Routing rules and DNS" (the guard's port, watch, own status, no-nf_tables decision) and "Repository layout" (the agent composes the guard); TP-048 Notes corrected
- 2026-10-14 in-progress → review — round 2: every finding checked; `make lint` (with the Android build), `make test`, race on routetable, agent and lists, `make lab-gotest` for firewall and routetable, and `make lab-test LAB_P=2` (lab and 29 in-node packages) pass; the macOS checklist box stays open (macOS pf pending TP-019)
