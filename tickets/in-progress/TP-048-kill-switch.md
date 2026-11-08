---
id: TP-048
title: "Kill switch (macOS and Linux)"
milestone: M2
area: dataplane/firewall
stream: core
repo: thinkpol-vpn
size: L
depends_on: [TP-046, TP-021, TP-078, TP-091, TP-166]
refs: [D4]
needs_human: macos
owner: "agent-tp-048"
branch: "tp-048-kill-switch"
---

## Goal
With the kill switch on, nothing leaves the device when the tunnel is down.

## Scope
- Firewall rules per OS: pf anchor (macOS), nftables (Linux): only entry endpoints allowed, plus LAN with allow-LAN.
- Temporary pause for captive portals.
- Rules stay in place if the service crashes, until it restores them.

## Acceptance
- [ ] with the service from TP-046, a simulated agent crash keeps traffic fail-closed until the restarted agent is back (macOS and Linux)
- [ ] killing the service with the kill switch on leaves no traffic flowing except to entries, on macOS and Linux
- [ ] after the agent crashes (killed, not stopped) with the "everything" or "all but domestic" preset and the kill switch off, nothing leaves except traffic to entries (and LAN with allow-LAN) until the agent starts and connects again, on macOS and Linux; opt-out is a setting
- [ ] a deliberate disconnect with the kill switch off removes the guard and traffic flows direct; with the switch on it stays

## Notes
- A pf guard for macOS doesn't exist yet; it comes with TP-078 (split from TP-021).
- **From TP-014 (egress):** an exit without IPv6 refuses a device's IPv6 with ICMPv6 "no route" rather than dropping it; the kill switch still has to block IPv6 outside the tunnel on the device, and must let the tunnel's own transport sockets out whatever the rules.

- **From TP-057 (route table):** sockets bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, an `IP_PKTINFO` ifindex) bypass the route table by design (gateways must resolve on the physical side); while connected they leave by main's default route, both families. Only the firewall can confine them: allow the mark 0x7470 and the entries, direct destinations and (with allow-LAN) the LAN, drop the rest on physical interfaces. `routetable.TestGatewaysOnLinksAndBoundSockets` documents today's behaviour. Also: IPv4's unreachable default in table 0x7470 is there only while the TUN is down (TP-057), so after a crash IPv4 flows; with the kill switch on, the firewall keeps it in.
- **Crash posture (independent design review, 2026-10-13; TP-062).** Fail-closed after an agent crash is the default for the "everything" and "all but domestic" presets (opt-out); a deliberate disconnect still follows the kill-switch toggle (PRD D4, off by default). Today's behaviour, from TP-018 (done): after a crash IPv4 flows and IPv6 is unreachable but for direct destinations. The firewall rules therefore stay after a crash for those presets even with the toggle off, and are removed on a deliberate disconnect; macOS must meet this too (docs/design/security.md "Kill switch"). TP-019 (macOS data plane) is in review, so its ticket isn't changed: this ticket and TP-046 carry the note.
- **From TP-021 (IPv6 leak guard, Linux; corrected in its review):** the kill switch is a separate owner from the IPv6 leak guard and shares only the shape of `routetable.Exempt` (TUN, Mark, Direct, Upstreams). The guard is the route table's: `firewall.IPv6Guard`, table `inet thinkpol-guard`, applied by the Enforcer with the routes and removed with them, so it lives and dies with the connection. The kill switch gets its own table (`inet thinkpol-killswitch`) with its own `exempt4`/`exempt6` sets, applied by the agent from the toggle and the preset, and it survives a disconnect (and, per the crash posture below, a crash). Its chain must also sit late in output (the guard hooks at NF_IP6_PRI_LAST so no route chain re-marks after it), exempt neighbour discovery and MLD only with their hop limits (255, 1) on Linux (pf can't match a hop limit, so on macOS the exemption is by ICMPv6 type and destination, as the IPv6 guard's is: say what that lets through), and, on macOS, exempt the direct DNS upstreams by address (no socket mark there). `TestGatewaysOnLinksAndBoundSockets` still shows IPv4 bound sockets leaving by main's default route.
- macOS (TP-138 review, 2026-10-28): lift the guard's `rulesOf` to a free function over pfctl and reuse `AnchorMissing`, `noTable`, `onlyLine` and `readLines`; don't copy them.
- macOS (TP-138 review, 2026-10-28): the guard's Close flushes rules before Tables, so a Close whose Tables step fails leaves the anchor without rules (IPv6 unconfined) while keeping the record. Don't assume a failed guard Close stays confined. Flushing Tables first may fail closed instead; this needs a device check before anyone relies on it.
- **TP-139 verdicts (TP-139 owner session, 2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** The kill switch, allow-LAN and pause are device-level settings: a member of the access group changes them through the local API, and the service stores them in the device store TP-166 builds. Their node defaults live in the node file. Toggles take `on|off` and have the `<setting> [value]` shape (`kill-switch on`). Depends on TP-166.

### Design (implementer, 2026-11-09)

**Objects.** The kill switch is its own owner, apart from the IPv6 leak guard (which stays the connection's).
- Linux: nftables table `inet thinkpol-killswitch` (`firewall.KillSwitchTable`), interval sets `allow4` and `allow6`, one chain `output` hooked at output, priority NF_IP_PRI_LAST (as the guard's: no route chain re-marks after it), policy accept:

  ```
  oifname "lo" accept
  oifname <TUN> accept                                 (connected only)
  meta mark 0x7470 accept                              (the links' and the direct DNS upstreams' sockets)
  ip daddr @allow4 accept
  ip6 daddr @allow6 accept
  meta nfproto ipv4 udp sport 68 udp dport 67 accept   (DHCPv4)
  meta nfproto ipv6 udp sport 546 udp dport 547 accept (DHCPv6)
  icmpv6 type 133-137 ip6 hoplimit 255 accept          (neighbour discovery)
  icmpv6 type { 130-132, 143 } ip6 hoplimit 1 accept   (MLD)
  meta l4proto tcp reject with tcp reset
  reject with icmpx admin-prohibited
  ```

  Replaced whole in one transaction, compared whole on a re-apply, as the guard's table is (shared helpers, not copies). Both tables must accept a packet: an accept ends only its own chain.
- macOS: anchor `com.apple/001.thinkpol-killswitch` under Apple's hook, sorting after the guard's `000.thinkpol` (the guard counts any anchor before its own as a bypass), one table `<thinkpol_killswitch>` (both families), loaded with the rules in one `pfctl -f - -o none`, read back (rules checked for their words, table entry for entry) and compared exactly on every re-apply:

  ```
  pass out quick on lo0 all no state
  pass out quick on <utun> all no state                                             (connected only)
  pass out quick from any to <thinkpol_killswitch> no state
  pass out quick proto { tcp, udp } from any to <upstream> port <its port> no state (each direct DNS upstream, connected only)
  pass out quick inet proto udp from any port 68 to any port 67 no state            (DHCPv4)
  pass out quick inet6 proto udp from any port 546 to any port 547 no state         (DHCPv6)
  pass out quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136, 137 } no state (ND)
  pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state (MLD)
  block return out quick all
  ```

  pf can't match a hop limit: ND types pass to any destination (a router could forward them; nothing else), MLD only to multicast. pf is enabled by a reference of the kill switch's own (`pfctl -E`, record `pf-killswitch.token` next to the guard's, same rules as the guard's: stamped with the boot, released with `-X` only while `-s References` lists it as ours); the guard's reference goes on a disconnect, the kill switch's must not. The reference machinery is the guard's, shared, not copied; so are the readers (`rulesOf`, `AnchorMissing`, `noTable`, `onlyLine`, `readLines`, `parseTable`, `parseStateAddrs`). After a load or an enable it kills the states (both families) whose remote end isn't in its table: pf passes a state without rules. Not done here: the guard's bypass walk (quick passes above the hook, earlier anchors) for IPv4; the hook itself is checked (no hook: not enforced, retried).
- While the guard is in place (connected, or after a crash), its quick passes decide IPv6 first: what it passes is what the connected shape passes, but link-local unicast and multicast (fe80::/10, ff02::/16), which the guard passes whole. A skipped interface (`set skip on`) is filtered by no rule at all: lo0 (passed anyway) costs nothing; any other skipped interface carries everything around the kill switch. TP-143: pfctl never showed `(skip)` on a device, so the kill switch doesn't read the skip set; the device checks look at it by hand.

**What it lets out.** The allow sets hold:
- always: the entries, every endpoint address of the device's links in its current section, as whole addresses, both families (none while the device is removed from its space); on Linux also the links' marked sockets;
- while connected: what the route table sends direct, `routetable.GuardFor` of the last Want (the rules' direct destinations, both families, and the endpoints), plus the TUN; on macOS also DNS to the direct upstreams on their ports (no socket mark there; their sockets are bound to the physical interface);
- with allow-LAN: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32, fe80::/10, fc00::/7, ff00::/8 (`firewall.LAN`);
- always: loopback, DHCP (v4 and v6) and, on the link, neighbour discovery and MLD, without which the uplink itself drops.

  Everything else is refused, not dropped (a reset, an ICMP error), so apps fail at once. Interface-bound sockets (TP-057's note) meet the same table: it is on output, not on routes.

**When it is in place (the agent decides; `firewall` only applies and removes).** The kill switch is wanted on a device in device mode whose map makes it a device (a mode mismatch leaves the host alone, as now) when:
- the toggle is on: always, the down shape while not connected;
- the toggle is off, the preset is "everything" or "all but domestic" and the crash posture isn't opted out: while the connection is meant up (connecting, connected, retrying, removed), so a crash leaves it; a deliberate disconnect removes it.

Shapes: connected (the engine up) is the connected shape; anything else is the down shape. The agent applies the wanted state at start (before connecting: a crashed run's connected shape is narrowed to the down shape until the restarted agent is connected again), on every change of the connection, the map, the preset or the toggles, and re-applies it every 10 s (a re-apply only checks it is whole: `nft flush ruleset` or `pfctl -F` is put back within 10 s). A failed apply is retried at the next of these and shows in the status (`kill_switch_enforced` false, the error's code). A failure never fails a connect.

**Crash posture.** The table and the anchor outlive the process. A crash (SIGKILL) leaves the shape in place (the connected shape: entries, direct destinations, LAN with allow-LAN; the TUN is gone with the process); the service restarts the agent within seconds, which applies the down shape at once and the connected shape once connected. Residual: until that restart, the last preset's direct destinations stay reachable as they were while connected (that traffic never went through the tunnel).

**A stop is not a disconnect.** The node returning (SIGTERM, a service stop, an update replacing the binary) leaves what a crash would, in the down shape: an update that fails to start leaks nothing. Only a deliberate `thinkpol disconnect` with the toggle off, a start that comes up disconnected with the toggle off, or `thinkpol service uninstall` (`Platform.ClearHost`) removes it. To stop the service and get direct traffic, disconnect first.

**Settings flow.** Device toggles (docs/design/configuration.md "Device level"): `kill_switch` and `allow_lan` in device.json, set through the local API (`SetKillSwitch`, `SetAllowLAN`, the access group), taking effect at once; written once a member set them, until then the node's defaults hold. Node defaults in node.json, as `up`'s flags in snake_case: `kill_switch` (-kill-switch, default false, PRD D4), `allow_lan` (-allow-lan, default false), `fail_closed_after_crash` (-fail-closed-after-crash, default true: the crash posture's opt-out, an operator's setting). CLI: `thinkpol kill-switch [on|off]` and `thinkpol allow-lan [on|off]` (no value shows it; a group prefix can't also be a command, so allow-LAN is its own). Status gets `kill_switch`, `allow_lan`, `kill_switch_enforced` (in place as wanted, or rightly absent) and `kill_switch_error`. TP-167 aligns exit codes later.

**Pause (proposed split).** The captive-portal pause (a member lifts the kill switch for a bounded time, stored as a deadline in device.json, put back when it ends or the agent restarts after it) is in Scope but in no acceptance box; this branch builds the kill switch, allow-LAN and the crash posture on both OSes, and proposes the pause as its own ticket.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
- 2026-10-12 docs (TP-057 review): interface-bound sockets are the firewall's to confine
- 2026-10-13 docs (TP-062): crash posture: fail-closed by default under the everything and all-but-domestic presets
- 2026-10-14 docs (TP-021): notes from the IPv6 leak guard on Linux
- 2026-10-14 docs (TP-021 review): the kill switch is its own owner and table; only Exempt's shape is shared
- 2026-10-15 docs (independent review 2026-10-15): retitled to macOS and Linux; milestone M2; depends on TP-021 not TP-047; needs_human macos; Windows/WFP moved to TP-076; note on missing macOS pf guard
- 2026-10-15 docs (TP-078 split): depends on the macOS pf IPv6 leak guard
- 2026-10-15 docs (backlog grooming, review fixes): acceptance for fail-closed gap after crash with TP-046 service
- 2026-10-16 docs (device testing rethink): depends on TP-091, whose `diag` snapshot is the evidence for its device run
- 2026-10-22 docs (TP-077 residual-risks research): the hop-limit exemption for ND/MLD is Linux-only; pf can't express it
- 2026-10-28 docs (TP-138 review): notes on reusing the guard's pfctl readers and on a failed guard Close
- 2026-11-07 TP-139 verdicts noted
- 2026-11-09 backlog → in-progress, owner: agent-tp-048
