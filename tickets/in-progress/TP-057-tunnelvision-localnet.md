---
id: TP-057
title: "Route table: close LocalNet and overlay TunnelVision paths"
milestone: M1
area: dataplane/routetable
repo: thinkpol-vpn
size: M
depends_on: [TP-018]
refs: [R2, D6, DESIGN#routing-rules-and-dns]
owner: "agent-tp-018"
branch: "tp-057-tunnelvision-localnet"
---

## Goal
No route the local network can plant (DHCP addresses and classless routes, router advertisements, PPP peers) takes foreign or overlay traffic around the tunnel on a Linux device in route-table mode.

## Scope
1. **LocalNet (TunnelCrack).** A censor's DHCP can assign e.g. 1.1.1.50/24 (the kernel adds 1.1.1.0/24 on-link) or a PPP peer /32; kernel-processed router advertisements add on-link routes for any advertised prefix (e.g. 2001:4860:4860::/64). `TrustedOnLink` trusts only on-link subnets entirely inside `lists.Local()` (RFC 1918, link-local, ULA); the length rule goes. DESIGN states the cost: hosts on a public on-link LAN go through the tunnel unless the rules send them direct (a later setting could opt in).
2. **Overlay TunnelVision.** The overlay is never looked up in main: table 0x7470 gets `<overlay> dev <TUN>` and `unreachable <overlay>` (metric 2048), and the overlay's rule becomes `to <overlay> lookup 0x7470`, ahead of the on-link mirror rules, without a mark condition. Trusted on-link subnets overlapping the overlay are dropped.
3. **Crash, then a failed start:** clear the route table when a device goes down with no engine running, and in start-failure paths before an Enforcer exists.
4. After the watcher restarts following an Enforce, re-apply once, in case events were missed meanwhile.
5. A kernel without rule protocols (`ErrUnsupported`) is terminal for the route table: no retry loop; the status says so.
6. Fix TP-018's stale done-ticket Notes.
7. Check that vishvananda/netlink's RuleList round-trips absent SuppressPrefixlen/Goto/Flow as -1, so rule 5301 isn't re-added on every re-apply.

## Out of scope
An opt-in to keep a public on-link LAN out of the tunnel (a later setting); firewall-level leak blocking (TP-021, TP-048).

## Acceptance
- [x] namespace tests: with 198.51.100.50/24 on the physical interface and an RA-style on-link 2001:db8:ab::/64, foreign destinations in those ranges still enter the TUN — `internal/dataplane/routetable` `TestHostileLocalNetworkRoutes` (198.51.100.9 and 2001:db8:ab::9 into the TUN; a private 10.9.0.0/24 LAN still on-link; with the overlay IPv4-only the advertised IPv6 prefix is unreachable); `TestTrustedOnLink`, `TestConfigLayout` (1.1.1.0/24, a /32 peer, 8.0.0.0/8 never trusted)
- [x] namespace tests: with an option-121-style 100.64.0.0/24 via the LAN gateway, an address inside the overlay /16 on the physical interface, and an on-link prefix inside the overlay's IPv6 /48, overlay traffic still enters the TUN — same test (100.64.0.9, 100.64.7.7, fd12:3456:789a:1::9 into the TUN; unreachable for the IPv6 one with IPv6 off)
- [x] lab: a crash, then a start that fails, leaves no route-table rules or routes — `lab/routetable_test.go` (kill -9 while connected, then `thinkpol up -interface eth0`, which fails creating the TUN: rules and proto-86 routes gone); agent `TestAFailedStartClearsACrashedRunsRouteTable`
- [x] a kernel without rule protocols stops the route table for good, visible in the status — `TestEnforcerStopsOnAnUnsupportedKernel` (no Apply retried, `Status.Error` = `routetable.ErrorUnsupported`, Enforce refuses at once; the agent's health shows `route_table_not_enforced`; a first start fails with it)

Evidence: see Log.

## Notes
- From the post-merge leak check of TP-018 (orchestrator decisions 1–6 in Scope).
- **Layout now** (DESIGN.md "Routing rules and DNS", route table on Linux), per family, after review:
```
rule 5298: oif <every link but the TUN and lo> lookup main suppress_prefixlength 0   proto 86
rule 5299: to <overlay network> lookup 29808
rule 5300: to <on-link subnet inside lists.Local() ∩ Direct> lookup main suppress_prefixlength 0
rule 5301: not fwmark 0x7470 lookup 29808
table 29808: <overlay> dev <TUN>, unreachable <overlay> metric 2048,
             default dev <TUN>, unreachable ::/0 metric 2048,
             unreachable 0.0.0.0/0 metric 2048 only while the TUN is down,
             throw <direct prefix>, throw <endpoint>
```
- **Found while testing decision 1 (not in the leak check):** IPv4 resolves the gateway of a main-table route through the policy rules (the kernel's `fib_check_nh` does a full lookup unless the route is in another table), with the route's device as `oif`. With public on-link subnets no longer trusted, a DHCP client's `default via 198.51.100.1 dev eth0` on a public LAN failed (the lookup met table 0x7470's unreachable default first), and the same for a new private subnet before the watcher mirrors it (roaming while connected; TP-018 had that race too); without `dev` the default route even resolved into the TUN. Fixed by the `oif` rules (5298 after review, so a gateway inside the overlay's range resolves too) and by keeping IPv4's unreachable default out of the table while the TUN is up: a reject route stops a lookup before its `oif` is checked, while the TUN's own default, bound to the TUN, lets an `oif eth1` lookup through to main. So a gateway on an interface created a moment ago resolves before any rule names it. The price: when the TUN goes down, IPv4 falls through to main for the debounce (200 ms) until the re-apply puts the unreachable default in; and after a crash IPv4 flows (D4) while IPv6 stays unreachable until the next start. A gateway route added *without* its device still resolves through the tunnel (DHCP clients always give the device).
- **Interface-bound sockets** (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, `IP_PKTINFO` ifindex: `ping -I`, NetworkManager's connectivity checks, resolved's per-link DNS) aren't confined by routing: both families leave by main's default route. Handed to TP-021 and TP-048 (their Notes); `TestGatewaysOnLinksAndBoundSockets` documents today's behaviour for them to flip.
- vishvananda/netlink v1.3.1 `RuleList` starts every rule from `NewRule()` (SuppressPrefixlen, SuppressIfgroup, Goto, Flow all -1) and sets them only from attributes the kernel sends, which it sends only when set: rules round-trip, so 5301 isn't re-added. Checked on the kernel too: netcfg `TestPolicyRoutingIsAppliedAndRemoved` re-applies with `Watch` subscribed and sees no deletion.
- The watcher re-applies once right after each Enforce (subscribed first, then the check), for what changed while it was paused; tests count it.
- An unsupported kernel is terminal in the Enforcer (no watcher retries, Enforce refuses at once). The agent's own Apply retry loop then fails fast each time; on a device the first start already fails, so `thinkpol up` exits with the reason.
- On-link trust after review: only subnets inside `lists.Local()` ∩ `Want.Direct` (`TrustedOnLink(p, direct)`): where the rules tunnel or block a private range, being on-link doesn't override them.
- Cost of decision 1, in DESIGN: hosts on a public on-link LAN go through the tunnel unless direct by rules; a DHCP server on such a LAN gets unicast renewals through the tunnel (they fail; the client falls back to broadcast, `255.255.255.255` is direct). A later setting could opt a LAN in.
- TP-018's done ticket: its TP-021/TP-048 notes (lines 71–72) said IPv4 had no fallback; corrected, and its layout points here.

## Review findings
Review: no new leak for unbound traffic. Orchestrator decisions:

- [x] 1 The oif rules go below 5299 (e.g. 5298), so an access gateway inside the overlay's range resolves. Namespace test: DHCP 100.64.20.5/24, gateway 100.64.20.1 on eth0, overlay 100.64.0.0/16 → the default route is added and link sockets work.
- [x] 2 oif rules for every link but the TUN and lo (from the link list, up or not), re-applied on RTM_NEWLINK. Test: a second dummy interface created after Enforce, an address and a default route via a public gateway on it at once (no sleep) → the route add succeeds.
- [x] 3 Decision: an on-link subnet is trusted only inside `lists.Local()` ∩ the effective Direct set (a hostile network can't widen it against the rules; where the rules block or tunnel a private range, on-link doesn't override). Test: `cidr:10.20.0.0/16 -> chain:x` + DHCP 10.0.0.50/8 → 10.20.1.5 enters the TUN. DESIGN.
- [x] 4 DESIGN and Notes: interface-bound sockets (SO_BINDTODEVICE, IP_UNICAST_IF, PKTINFO ifindex; NetworkManager's connectivity checks, resolved's per-link DNS, `ping -I`) can't be confined by routing: hand them to TP-021/TP-048 (firewall) in their Notes with a Log line; a bound-socket test documents today's behaviour (`ip route get … oif eth0`) so a firewall ticket can flip it.

Resolution:
- 1 The `oif` rules are at 5298 (`routetable.PriorityLinks`). `TestGatewaysOnLinksAndBoundSockets`: 100.64.20.5/24 on eth0 with the overlay 100.64.0.0/16, `default via 100.64.20.1 dev eth0` is added, marked (link) packets leave through it, overlay and foreign traffic still enter the TUN.
- 2 One `oif` rule per link but the TUN and lo (`netcfg.Survey.Links`, up or not), re-applied on link events. A gateway on a link created a moment ago resolves even before its rule exists, because IPv4's unreachable default is now in the table only while the TUN is down (see Notes). Test: eth1 created after Enforce, address and `default via 203.0.113.1 dev eth1` at once: added, and the rule for eth1 follows.
- 3 `TrustedOnLink(p, direct)` trusts only inside `lists.Local()` ∩ the Want's Direct set. Test: Direct without 10.20.0.0/16 (as `cidr:10.20.0.0/16 -> chain:x` makes it), 10.0.0.50/8 on eth0: 10.20.1.5 enters the TUN, 10.21.0.5 stays on-link; `TestTrustedOnLink`. DESIGN.md.
- 4 DESIGN.md and Notes; TP-021 and TP-048 Notes with Log lines; `TestGatewaysOnLinksAndBoundSockets` asserts today's behaviour (`ip route get … oif eth0`: both families out of eth0 by main's default).

## Log
- 2026-10-12 created in in-progress — owner: agent-tp-018, branch: tp-057-tunnelvision-localnet (follow-up to TP-018's post-merge leak check)
- 2026-10-12 docs: TP-018's done Notes corrected (TP-021, TP-048: IPv4 has the unreachable fallback; layout superseded here); DESIGN.md "Routing rules and DNS" (route table on Linux: overlay in its own table, local-only on-link, oif rules)
- 2026-10-12 merged origin/rewrite (TP-014); in-progress → review — every acceptance box checked; `make lint`, `make test`, `go test -race` on dataplane, routetable, netcfg and agent, and `make lab-test LAB_P=2` (lab and 28 in-node packages) pass
- 2026-10-12 review → has-errors — findings 1–4 (see Review findings)
- 2026-10-12 has-errors → in-progress — owner: agent-tp-018, picking up the review findings
- 2026-10-12 review fixes 1–4; DESIGN.md "Routing rules and DNS" (oif rules for every link at 5298, on-link trust inside Local ∩ Direct, IPv4's unreachable default only while the TUN is down, interface-bound sockets); TP-021 and TP-048 Notes
