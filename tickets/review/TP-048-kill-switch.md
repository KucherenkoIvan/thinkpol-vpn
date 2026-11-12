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
- ~~Temporary pause for captive portals.~~ Moved out: a separate M2 ticket (owner, 2026-11-09; own ticket, filed at merge).
- Rules stay in place if the service crashes, until it restores them.

## Acceptance
- [ ] with the service from TP-046, a simulated agent crash keeps traffic fail-closed until the restarted agent is back (macOS and Linux)
  - Linux: proven in the lab on ea51a26 (`TestKillSwitchUnderSystemd`: SIGKILL with the restart held off, then the restart; `TestKillSwitchDirectDestinationsExpireWithoutTheAgent`). macOS: device checks 8–9 below.
- [ ] killing the service with the kill switch on leaves no traffic flowing except to entries, on macOS and Linux
  - Linux: proven in the lab on ea51a26 (`TestKillSwitchUnderSystemd` "on, crashed": ping, TCP and a curl bound to eth0, both families; the entries answer). A stop leaves the down shape (`TestTheCrashPostureHoldsWhileMeantUp`). macOS: device check 8.
- [ ] after the agent crashes (killed, not stopped) with the "everything" or "all but domestic" preset and the kill switch off, nothing leaves except traffic to entries (and LAN with allow-LAN) until the agent starts and connects again, on macOS and Linux; opt-out is a setting
  - Linux: proven in the lab on ea51a26 (`TestKillSwitchUnderSystemd` "everything, crashed"; allow-LAN in "on, disconnected, allow-LAN"; the opt-out `fail_closed_after_crash: false` in node.json: "opted out, crashed"). macOS: device check 9; pf can't expire the direct destinations (RR18).
- [ ] a deliberate disconnect with the kill switch off removes the guard and traffic flows direct; with the switch on it stays
  - Linux: proven in the lab on ea51a26 (`TestKillSwitchUnderSystemd` "off, disconnected", "everything, disconnected", "on, after a disconnect"). macOS: device checks 7 and 10.

## Notes
- A pf guard for macOS doesn't exist yet; it comes with TP-078 (split from TP-021).
- **From TP-014 (egress):** an exit without IPv6 refuses a device's IPv6 with ICMPv6 "no route" rather than dropping it; the kill switch still has to block IPv6 outside the tunnel on the device, and must let the tunnel's own transport sockets out whatever the rules.

- **From TP-057 (route table):** sockets bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, an `IP_PKTINFO` ifindex) bypass the route table by design (gateways must resolve on the physical side); while connected they leave by main's default route, both families. Only the firewall can confine them: allow the mark 0x7470 and the entries, direct destinations and (with allow-LAN) the LAN, drop the rest on physical interfaces. `routetable.TestGatewaysOnLinksAndBoundSockets` documents today's behaviour. Also: IPv4's unreachable default in table 0x7470 is there only while the TUN is down (TP-057), so after a crash IPv4 flows; with the kill switch on, the firewall keeps it in.
- **Crash posture (independent design review, 2026-10-13; TP-062).** Fail-closed after an agent crash is the default for the "everything" and "all but domestic" presets (opt-out); a deliberate disconnect still follows the kill-switch toggle (PRD D4, off by default). Today's behaviour, from TP-018 (done): after a crash IPv4 flows and IPv6 is unreachable but for direct destinations. The firewall rules therefore stay after a crash for those presets even with the toggle off, and are removed on a deliberate disconnect; macOS must meet this too (docs/design/security.md "Kill switch"). TP-019 (macOS data plane) is in review, so its ticket isn't changed: this ticket and TP-046 carry the note.
- **From TP-021 (IPv6 leak guard, Linux; corrected in its review):** the kill switch is a separate owner from the IPv6 leak guard and shares only the shape of `routetable.Exempt` (TUN, Mark, Direct, Upstreams). The guard is the route table's: `firewall.IPv6Guard`, table `inet thinkpol-guard`, applied by the Enforcer with the routes and removed with them, so it lives and dies with the connection. The kill switch gets its own table (`inet thinkpol-killswitch`) with its own `allow4`/`allow6` and `direct4`/`direct6` sets (named `exempt4`/`exempt6` here before it was built), applied by the agent from the toggle and the preset, and it survives a disconnect (and, per the crash posture below, a crash). Its chain must also sit late in output (the guard hooks at NF_IP6_PRI_LAST so no route chain re-marks after it), exempt neighbour discovery and MLD only with their hop limits (255, 1) on Linux (pf can't match a hop limit, so on macOS the exemption is by ICMPv6 type and destination, as the IPv6 guard's is: say what that lets through), and, on macOS, exempt the direct DNS upstreams by address (no socket mark there). `TestGatewaysOnLinksAndBoundSockets` still shows IPv4 bound sockets leaving by main's default route.
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
  meta nfproto ipv6 udp sport 546 udp dport 547 ip6 daddr { ff02::1:2, fe80::/10 } accept (DHCPv6)
  icmpv6 type 133-137 ip6 hoplimit 255 accept          (neighbour discovery)
  icmpv6 type { 130-132, 143 } ip6 hoplimit 1 accept   (MLD)
  meta l4proto tcp reject with tcp reset
  reject with icmpx admin-prohibited
  ```

  A second base chain, `forward` (hook forward, the same last priority, R1.1), confines what the device routes for others (container bridges, VM NAT, a hotspot), which never meets output: `oifname <TUN>` and `iifname <TUN>` accept (connected only), then daddr in the four sets, then their replies by saddr in conntrack's reply direction only, then the same two rejects. Not postrouting: reject is refused there.

  Replaced whole in one transaction, compared whole on a re-apply, as the guard's table is (shared helpers, not copies). Both tables must accept a packet: an accept ends only its own chain.
- macOS: anchor `com.apple/001.thinkpol-killswitch` under Apple's hook, sorting after the guard's `000.thinkpol` (the guard counts any anchor before its own as a bypass), one table `<thinkpol_killswitch>` (both families), loaded with the rules in one `pfctl -f - -o none`, read back (rules checked for their words, table entry for entry) and compared exactly on every re-apply:

  ```
  pass out quick on lo0 all no state
  pass out quick on <utun> all no state                                             (connected only)
  pass out quick from any to <thinkpol_killswitch> no state
  pass out quick proto { tcp, udp } from any to <upstream> port <its port> no state (each direct DNS upstream, connected only)
  pass out quick inet proto udp from any port 68 to any port 67 no state            (DHCPv4)
  pass out quick inet6 proto udp from any port 546 to { ff02::1:2, fe80::/10 } port 547 no state (DHCPv6)
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

**Crash posture.** The table and the anchor outlive the process. A crash (SIGKILL) leaves the shape in place (the connected shape: entries, direct destinations, LAN with allow-LAN; the TUN is gone with the process); the service restarts the agent within seconds, which applies the down shape at once and the connected shape once connected. On Linux the direct destinations are a dead-man's switch: they sit in their own sets (`direct4`, `direct6`, flags interval,timeout, 30 s), renewed by every apply (the agent re-applies every 10 s), so a dead agent's table lets out only the entries within 30 s (found in the lab: the M0 map has no rules, so everything is direct, and the first lab run showed a crashed agent's connected shape passing everything). pf can't expire a table entry: on macOS they stay until the restarted agent narrows them (RR18).

**A stop is not a disconnect.** The node returning (SIGTERM, a service stop, an update replacing the binary) leaves what a crash would, in the down shape: an update that fails to start leaks nothing. Only a deliberate `thinkpol disconnect` with the toggle off, a start that comes up disconnected with the toggle off, or `thinkpol service uninstall` (`Platform.ClearHost`) removes it. To stop the service and get direct traffic, disconnect first. Owner, 2026-11-09: kept; a stop fails closed like a crash. The agent warns as it stops with it in place, `kill-switch`'s help says so, and the documented way out is `sudo thinkpol rollback` (TP-134, not built yet; until then `thinkpol disconnect`, which is recorded even when the node can't act on it, R1.4).

**Settings flow.** Device toggles (docs/design/configuration.md "Device level"): `kill_switch` and `allow_lan` in device.json, set through the local API (`SetKillSwitch`, `SetAllowLAN`, the access group), taking effect at once; written once a member set them, until then the node's defaults hold. Node defaults in node.json, as `up`'s flags in snake_case: `kill_switch` (-kill-switch, default false, PRD D4), `allow_lan` (-allow-lan, default false), `fail_closed_after_crash` (-fail-closed-after-crash, default true: the crash posture's opt-out, an operator's setting). CLI: `thinkpol kill-switch [on|off]` and `thinkpol allow-lan [on|off]` (no value shows it; a group prefix can't also be a command, so allow-LAN is its own). `SetKillSwitch` and `SetAllowLAN` return once the node acted on the change (as `SetRulePreset` does), so the status they return shows it. Health: `kill_switch_not_enforced`, `kill_switch_unsupported` (degraded). Status gets `kill_switch`, `allow_lan`, `kill_switch_enforced` (in place as wanted, or rightly absent) and `kill_switch_error`. TP-167 aligns exit codes later.

**Pause.** The captive-portal pause (a member lifts the kill switch for a bounded time, stored as a deadline in device.json, put back when it ends or the agent restarts after it) is not built here: a separate M2 ticket (owner, 2026-11-09), filed at this ticket's merge.

### Device checks for the M2 acceptance run (macOS)

Run on the owner's Mac with thinkpol installed as the service (`sudo thinkpol service install`) in a space with an entry. `<entry>` is an entry's IPv4 endpoint address, `<router>` the Wi-Fi router's address. Record every pfctl output named below in the run's evidence.

| # | Do | Expect |
|---|---|---|
| 0 | `sudo pfctl -s rules`; `sudo pfctl -s Interfaces -v` | `anchor "com.apple/*" all` is listed; note any interface but lo0 marked `(skip)` (RR57: it would carry everything past the kill switch) |
| 1 | `thinkpol disconnect`; `thinkpol kill-switch on` | `kill switch: on, allow-LAN off (in place)` |
| 2 | `sudo pfctl -a com.apple/001.thinkpol-killswitch -s rules`; `sudo pfctl -a com.apple/001.thinkpol-killswitch -t thinkpol_killswitch -T show`; `sudo pfctl -s References`; `sudo cat /private/var/db/thinkpol/pf-killswitch.token` | 15 rules, every pass `no state`, the last `block return out quick all`, no utun rule; the table lists the entries (IPv4 hosts without `/32`); References lists the record's token and pid. Record the listing: the IPv4 DHCP rule's, the two DHCPv6 rules' (to ff02::1:2 and fe80::/10) and the ND rules' text are unrecorded so far |
| 3 | `curl -m 5 https://example.net`; `curl -m 5 --interface en0 https://example.net`; `ping -c 1 <entry>`; `ping6 -c 1` a public IPv6 address | both curls fail at once (refused), the entry answers, the IPv6 ping fails |
| 4 | `thinkpol allow-lan on`; `ping -c 1 <router>`; `thinkpol allow-lan off`; `ping -c 1 <router>` | answered with allow-LAN on, refused off |
| 5 | `thinkpol connect`; browse; `sudo pfctl -a com.apple/001.thinkpol-killswitch -s rules`; `sudo pfctl -a com.apple -s Anchors`; `thinkpol status` | browsing works; the anchor passes the utun and DNS to the direct upstreams; Anchors lists `000.thinkpol` before `001.thinkpol-killswitch`; health has no `ipv6_guard_not_enforced` (the guard doesn't count the kill switch's anchor as a bypass) and no `kill_switch_not_enforced` |
| 6 | `sudo pfctl -s states \| head -20` | record it: IPv4 states read `addr:port` (the kill switch's state kill assumes it; unrecorded so far) |
| 7 | `thinkpol disconnect`; repeat 3 | still confined: a disconnect with the switch on keeps it (box 4) |
| 8 | `thinkpol connect`; `sudo launchctl kill SIGKILL system/org.thinkpol.agent`; at once repeat 3 (curls, entry ping); then `thinkpol status` until connected | confined while the agent is down (box 1, box 2), the entry answers; the restarted agent comes back connected, and browsing works again |
| 9 | `thinkpol kill-switch off`; `thinkpol rules preset everything`; `thinkpol connect`; `sudo launchctl kill SIGKILL system/org.thinkpol.agent`; at once repeat 3 | confined until the restarted agent is connected (box 3) |
| 10 | `thinkpol disconnect`; `sudo pfctl -a com.apple/001.thinkpol-killswitch -s rules`; `sudo pfctl -s References`; `curl -m 5 https://example.net` | no rules (`pfctl: DIOCGETRULES: Invalid argument` or an empty listing), the kill switch's reference gone, curl works: a deliberate disconnect with the switch off removes it (box 4) |
| 11 | `thinkpol kill-switch on`; `sudo thinkpol service uninstall`; repeat 10 | the anchor flushed, the reference released, `/private/var/db/thinkpol/pf-killswitch.token` gone, traffic flows |
| 12 | Forwarded traffic (R1.1): `sudo thinkpol service install`; `thinkpol disconnect`; `thinkpol kill-switch on`; turn on Internet Sharing to a second device, or start a VM on a shared (NAT) network; from the client: `curl -m 5 https://example.net`, `ping -c 1 <entry>`; `sudo pfctl -s states \| grep <the client's address>` | the curl fails at once (pf filters what the Mac forwards on its way out, the anchor's `block return out` included), the entry answers; record whether the client's traffic shows NATed to en0's address in the states (pf's `nat` for sharing runs before the anchor's filter) |

## Review findings
- [x] R1.1 (blocker, leak) Linux: the kill switch hooks only output, so forwarded traffic (container bridges, VM NAT, a hotspot) never meets it; add a forward chain with the same sets; firewall/doc.go's claim that routing keeps forwarded traffic in the tunnel is false while it is down. Lab test with a forwarding namespace; macOS: device check row for forwarded traffic
- [x] R1.2 the re-apply period is 20 s, not 10 s (reapplyAt measured after the tick is handled, so the next tick is skipped); direct sets renewed 10–20 s apart against a 30 s timeout. Re-apply every 10 s for real, consider a longer direct timeout, state the real numbers. Lab tests: a direct destination stays reachable after 45 s connected; `nft flush ruleset` → table back within 11 s
- [x] R1.3 after a crash restoreHost (RestoreDNS) runs before startKillSwitch, so on macOS the crashed run's anchor passes DNS to the upstreams while the OS points at them; start the kill switch before restoring the host on both OSes; unit test on the order
- [x] R1.4 a first start that keeps failing under the crash posture can only be escaped by uninstalling: `thinkpol disconnect` can't reach the node; Disconnect records the choice even when the node can't act on it, and the next run honours it. Test
- [x] R1.5 boot window undocumented: neither the table nor the anchor survives a reboot; RR row, and on Linux order the unit before network-pre.target (or say why not)
- [x] R1.6 a stop leaves the kill switch (or the crash posture) in place: log a Warn when the agent stops with it in place, saying only entries leave until the agent runs again and how to stop with traffic direct; the same sentence in `kill-switch`'s help. Semantics unchanged (owner decision pending)
- [x] R1.7 the shared pf code speaks only for the guard (errNoTable, errUnreadReferences, pfEnabler's docs, the kill switch translating routetable.ErrGuardUnsupported): move pfEnabler and the free helpers into pf_darwin.go with an owner string, add errNoPfctl that each owner wraps into its own unsupported error
- [x] R1.8 box 2's Linux half lacks the stop path: lab test `systemctl stop` → down shape in place and traffic confined, `systemctl start` → back
- [x] R1.9 nits: DHCP exemptions restricted (or an RR row); mode mismatch documented, SetKillSwitch's promise exact; typed KillSwitchStatus error codes and remove_failed; errKillSwitchClosed once; guardChain/guardPriority → outputChain/lastPriority; onOffArgs beside newAPICommand; firewall.LAN documented as the agent's definition; bounded shutdown/awaitSection contexts; status text "while the connection is meant up"; TP-021 note amended; pause out of Scope (own ticket, filed at merge)

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
- 2026-11-09 design in Notes; built: `firewall.KillSwitch` (Linux `inet thinkpol-killswitch`; macOS anchor `com.apple/001.thinkpol-killswitch` with its own pf enable reference: the guard's reference handling moved into a shared `pfEnabler`, its readers, flush and state kill shared, not copied), the agent's keeper (toggle, crash posture, a stop keeps it, uninstall removes it, re-applied every 10 s), local API `SetKillSwitch`/`SetAllowLAN` and `Status.kill_switch`, CLI `kill-switch [on|off]` and `allow-lan [on|off]`, node.json `kill_switch`/`allow_lan`/`fail_closed_after_crash`, device.json `kill_switch`/`allow_lan`, health `kill_switch_not_enforced`/`kill_switch_unsupported`; docs: firewall, agent and localapi package docs, security.md "Kill switch", configuration.md, api-overview.md (TP-048 section), RR17–RR21 narrowed, RR57–RR58 added
- 2026-11-09 found in the lab: a SIGKILLed agent's connected shape let everything out (the M0 map has no rules, so all is direct, and the lab's networks are private); the direct destinations now sit in expiring sets on Linux (30 s, renewed by every apply); pf can't expire an entry, so macOS keeps them until the restarted agent narrows them (RR18)
- 2026-11-09 mutations, unit (all caught): darwin state kill IPv6 only, no upstream rules, Close keeping the reference, no hook check, the listing unchecked, IPv4 `addr:port` not cut; agent opt-out ignored, no entries in the down shape, a stop removing it, no start narrowing, a failure reported as enforced, the member's toggle ignored; CLI kill-switch taking any argument; status text without "(in place)"
- 2026-11-09 mutations, lab (all caught): the final reject rule removed (`TestKillSwitchLetsOutOnlyEntriesWhileDown`), the direct sets not renewed (`TestKillSwitchDirectDestinationsExpireWithoutTheAgent`), the kill switch's table named as the guard's (`TestKillSwitchAndGuardAreSeparateOwners`), the direct sets without a timeout (`TestKillSwitchUnderSystemd`)
- 2026-11-09 the full lab failed `TestDiagShowsWhatTheHostHolds` once: under all-but-domestic the crash posture's chain refuses the guard's test ping before the guard's counts it (both are last at output); that test now runs with `-fail-closed-after-crash=false`
- 2026-11-09 make lint, make test and make lab-test green on ea51a26 (origin/rewrite at 44079f8 merged)
- 2026-11-09 not verified: everything on macOS (the anchor, its reference, pfctl's listing of the new rules, IPv4 in `-s states`, skipped interfaces): the device checks in Notes, for the M2 acceptance run (TP-029); the four boxes stay open for them, their Linux halves proven
- 2026-11-09 proposed split: the captive-portal pause as its own ticket (in Scope, in no box). Out of scope, for the board: `diag` doesn't show the kill switch's table, and the guard's counters miss what the kill switch's chain refuses first
- 2026-11-09 in-progress → review
- 2026-11-09 review → has-errors (round 1 findings R1.x)
- 2026-11-12 has-errors → in-progress
- 2026-11-12 handoff taken over from the stopped run (head ebb439e); its uncommitted file was its own forward-chain mutation, restored
- 2026-11-12 R1.1: `forward` base chain at the last priority (into/out of the TUN while connected, daddr in allow/direct, their replies by saddr in conntrack's reply direction only, the same rejects; not postrouting, where reject is refused); firewall doc.go's forwarding claim corrected; security.md; macOS device check 12. Lab `TestKillSwitchConfinesForwardedTraffic` (a client namespace forwarded by the device namespace: down, allow-LAN, connected, a flushed forward chain re-applied); mutation: forward chain dropped → the client's pings to foreign addresses answered (caught)
- 2026-11-12 R1.2: reapplyAt = now + period/2, so every 10 s tick re-applies (it was every other tick: 20 s); DirectTimeout kept at 30 s (20 s of node-loop stall margin; longer would leave a dead agent's direct destinations open longer), said in RR58, the agent and firewall docs. Unit `TestTheKillSwitchIsReappliedAtEveryTick` (mutation: the old reapplyAt → tick 1 skipped, caught); lab `TestKillSwitchUnderSystemd`: under everything a direct destination bound to eth0 answers after 45 s, the table deleted from outside right after a re-apply is back within 11 s, three times (the table, not `nft flush ruleset`, which would take the container's own rules); mutation: the old reapplyAt → back after ~20 s each time (caught)
- 2026-11-12 R1.3: startKillSwitch before restoreHost on both OSes (and after a mode mismatch ends). Unit `TestAStartNarrowsTheKillSwitchBeforeRestoringTheHost` (RestoreDNS sees the down shape); mutation: the old order → RestoreDNS sees the crashed run's connected shape (caught)
- 2026-11-12 R1.4: Disconnect records the choice (ConnectRecord) before the node hears of it; remember's writes serialized (the record's temporary file has one name). Unit `TestADisconnectTheNodeCantTakeIsHonouredAtTheNextStart` (a first start blocked then failing under everything; Disconnect gets ErrNotRunning, the next start comes up disconnected, the kill switch removed); mutation: Disconnect not recording → the record stays connect (caught)
- 2026-11-12 R1.5: RR59 (boot window); the unit is not ordered before network-pre.target: it is After=network.target and systemd-resolved (an ordering cycle), and Type=simple orders only the fork, not the first apply; closing it needs a oneshot (or a readiness notification) before network-pre.target and a boot-time pf rule: proposed for the board
- 2026-11-12 R1.6 (owner, 2026-11-09: a stop fails closed like a crash): the agent warns as it stops with the kill switch in place (`agent.KillSwitchStopNote`), the same sentence in `kill-switch`'s help; security.md names `sudo thinkpol rollback` (TP-134, not built yet) as the way out. Unit: `TestTheCrashPostureHoldsWhileMeantUp` checks the warning; mutation: no warning → caught
- 2026-11-12 R1.7: pfEnabler and the shared helpers moved into pf_darwin.go; listTable and flushAnchor take the owner's name, errNoTable/errUnreadReferences/parseTableOf speak for neither owner; errNoPfctl from execPfctl, wrapped by the guard into routetable.ErrGuardUnsupported and by the kill switch into ErrKillSwitchUnsupported. Unit: TestExecPfctl and TestKillSwitchNeedsTheHookAndPfctl check each owner's error alone; mutations: the kill switch not wrapping, the guard not wrapping (both caught)
- 2026-11-12 R1.8: lab `TestKillSwitchUnderSystemd`: `systemctl stop` → the table in the down shape and traffic confined (both families, bound or not), `systemctl start` → connected again with the connected shape
- 2026-11-12 R1.9: DHCPv6 restricted to ff02::1:2 and fe80::/10 on both OSes (lab probes in `TestKillSwitchLetsOutOnlyEntriesWhileDown`; mutation: the link-local range widened to all → DHCPv6 to the gateway's global address passes, caught); DHCPv4 left to any destination, RR60 says why; mode mismatch documented beside the routes note (agent doc.go) and SetKillSwitch's promise made exact (localapi doc.go); KillSwitchError typed codes with remove_failed (proto comment, make proto); errKillSwitchClosed once; outputChain/lastPriority; onOffArgs beside newAPICommand; firewall.LAN documented as the agent's definition; shutdown/awaitSection last apply bounded to 10 s; status text "while the connection is meant up"; TP-021 note amended; pause out of Scope (a separate M2 ticket, owner, 2026-11-09)
- 2026-11-12 also fixed: cmd/thinkpol's status test fake (from TP-168's merge) lacked SetKillSwitch/SetAllowLAN, so `cmd/thinkpol` tests didn't build on 2ed67b5
- 2026-11-12 make test green (the tree before the gofmt reflow and the nolint comment); make lint green up to vulncheck (gofmt, vet and golangci on darwin/linux/windows, Android build, no-cgo, proto-check); vulncheck fails on GO-2026-6859 (net/http in the go1.26.10 toolchain, fixed in go1.26.11), the same toolchain as origin/rewrite: out of scope, for the board
- 2026-11-12 make lab-test green on 2db6eff (origin/rewrite unchanged since the merge in 2ed67b5)
- 2026-11-12 not verified: everything on macOS (the restricted DHCPv6 rules as pfctl lists them, forwarded traffic through the anchor: device checks 2 and 12; the errNoPfctl and pf_darwin.go move are unit-tested with the fake pfctl only). Out of scope, for the board: RR59's boot window (a oneshot applying the down shape before network-pre.target, a boot-time pf rule); the go1.26.11 toolchain bump for GO-2026-6859; `diag` doesn't show the kill switch's table (from round 0)
- 2026-11-12 in-progress → review
