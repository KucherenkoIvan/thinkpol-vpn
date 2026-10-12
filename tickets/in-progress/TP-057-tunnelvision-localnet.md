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
- **Layout now** (DESIGN.md "Routing rules and DNS", route table on Linux), per family:
```
rule 5299: to <overlay network> lookup 29808                                  proto 86
rule 5300: to <on-link subnet inside the local ranges> lookup main suppress_prefixlength 0
rule 5300: oif <physical interface> lookup main suppress_prefixlength 0
rule 5301: not fwmark 0x7470 lookup 29808
table 29808: <overlay> dev <TUN>, unreachable <overlay> metric 2048,
             default dev <TUN>, unreachable default metric 2048,
             throw <direct prefix>, throw <endpoint>
```
- **Found while testing decision 1 (not in the leak check):** IPv4 resolves the gateway of a main-table route through the policy rules (the kernel's `fib_check_nh` does a full lookup unless the route is in another table). With public on-link subnets no longer trusted, a DHCP client's `default via 198.51.100.1 dev eth0` on a public LAN failed (the lookup met table 0x7470's unreachable default first), and the same goes for a new private subnet before the watcher mirrors it (roaming while connected; TP-018 had that race too); without `dev` the default route even resolved into the TUN. Fix: `oif <physical interface> lookup main suppress_prefixlength 0` for every interface with on-link routes but the TUN (`netcfg.Rule.Oif`, `netcfg.Survey.OnLinkInterfaces`): the kernel's lookup carries the route's device as `oif`. Side effects: sockets bound to a physical interface (`SO_BINDTODEVICE`) see main's specific routes (not its default); a gateway route added *without* its device still resolves through the tunnel (DHCP clients always give the device). `TestEnforcesInANamespace` and `TestHostileLocalNetworkRoutes` add default routes the way DHCP clients do and check they stay on eth0.
- vishvananda/netlink v1.3.1 `RuleList` starts every rule from `NewRule()` (SuppressPrefixlen, SuppressIfgroup, Goto, Flow all -1) and sets them only from attributes the kernel sends, which it sends only when set: rules round-trip, so 5301 isn't re-added. Checked on the kernel too: netcfg `TestPolicyRoutingIsAppliedAndRemoved` re-applies with `Watch` subscribed and sees no deletion.
- The watcher re-applies once right after each Enforce (subscribed first, then the check), for what changed while it was paused; tests count it.
- An unsupported kernel is terminal in the Enforcer (no watcher retries, Enforce refuses at once). The agent's own Apply retry loop then fails fast each time; on a device the first start already fails, so `thinkpol up` exits with the reason.
- Cost of decision 1, in DESIGN: hosts on a public on-link LAN go through the tunnel unless direct by rules; a DHCP server on such a LAN gets unicast renewals through the tunnel (they fail; the client falls back to broadcast, `255.255.255.255` is direct). A later setting could opt a LAN in.
- TP-018's done ticket: its TP-021/TP-048 notes (lines 71–72) said IPv4 had no fallback; corrected, and its layout points here.

## Log
- 2026-10-12 created in in-progress — owner: agent-tp-018, branch: tp-057-tunnelvision-localnet (follow-up to TP-018's post-merge leak check)
- 2026-10-12 docs: TP-018's done Notes corrected (TP-021, TP-048: IPv4 has the unreachable fallback; layout superseded here); DESIGN.md "Routing rules and DNS" (route table on Linux: overlay in its own table, local-only on-link, oif rules)
