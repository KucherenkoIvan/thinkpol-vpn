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
- [x] lab capture (Linux): no IPv6 packet leaves a physical interface outside the tunnel while connected — `lab/ipv6leak_test.go` `TestNoIPv6LeavesAroundTheTunnel`: device-a connected with "all but domestic" (`lab/maps/routetable.yaml`); `ping -6 -I eth0`, `ping -6 -I <eth0's address>`, unbound `ping -6` and `curl -6 --interface eth0` to a foreign IPv6 site; a capture of the device's own outgoing IPv6 on every lab interface shows only direct destinations (the domestic site, `local`: the lab's unique-local networks, link-local, multicast) and the entry's endpoint, and does show the direct ping (the capture works). The same with the overlay IPv4-only (`-link-mtu 1300`) and after a kill -9 while connected; `-connect=false` removes the guard, a clean stop too. Negative control (the guard disabled): the bound ping is answered and the capture shows ICMPv6 and TCP to the foreign site from the device's address.
- [ ] the macOS checklist (pf anchor): round 2, after TP-019 merges (see Notes)

## Notes
- **From TP-014 (egress):** an exit whose uplink has no IPv6 (no IPv6 default route, or only unique local addresses) refuses a device's IPv6 inside its namespace with ICMPv6 "no route", at once, and none leaves; the device must still keep IPv6 from going around the tunnel itself.

- **From TP-057 (route table):** sockets bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, an `IP_PKTINFO` ifindex: `ping -I eth0`, NetworkManager's connectivity checks, systemd-resolved's per-link DNS) can't be confined by routing: IPv4 and IPv6 both leave by main's default route (the rule `oif <link> lookup main suppress_prefixlength 0` at 5298 exists so the kernel can resolve gateways, and IPv4 would otherwise reach on-link hosts by ARP anyway). Block them in the firewall while connected (e.g. nftables: output on a physical interface, not marked 0x7470, not to a direct destination, not to the LAN), at least for IPv6 here. `internal/dataplane/routetable` `TestGatewaysOnLinksAndBoundSockets` documents today's behaviour (`ip route get … oif eth0`): flip its assertions when the firewall lands.

Evidence (round 1): `make lint` (with the darwin/linux/windows vets and the Android build), `make test`, `go test -race` on routetable, firewall, lists and dataplane, `make lab-gotest` for firewall and routetable, and `make lab-test LAB_P=2` with `THINKPOL_LAB_MAX_LABS=2` (every lab test, the new one included, and 29 in-node packages) pass.

**Round 1 (2026-10-14): Linux.** macOS waits for TP-019 (in review on its own branch, which also changes `routetable`); this round touches no darwin code but a stub.

*What "route IPv6 into the tunnel when the egress has it, block it otherwise" came to.* Routing already did the first half: the route table sends IPv6 into the TUN whenever the overlay carries IPv6 (`Want.IPv6`), and an exit without an IPv6 uplink refuses it there at once (TP-014); with the overlay IPv4-only, IPv6 meets table 0x7470's unreachable default but for direct destinations and endpoints (TP-018, TP-057). A device can't tell from its map whether its chain's exit has IPv6, and needn't: either way nothing goes around. What leaked was what routing can't see: sockets bound to an interface (rule 5298 routes them by main's default route), other software's routes or tables ahead of ours. The guard closes that for IPv6, whatever the egress.

*Design* (DESIGN.md "Routing rules and DNS", route table on Linux; "IPv6"):
- `internal/dataplane/firewall` (desktop-only, as before; its pure part builds everywhere): `Exempt{TUN, Mark, Direct}` and `Ranges6` (`guard.go`); `IPv6Guard` (`guard_linux.go`), one nftables table owned by its name:
```
table inet thinkpol-guard {
  set exempt6 { type ipv6_addr; flags interval; elements = Direct's IPv6 ∪ fe80::/10 ∪ ff02::/16, merged }
  chain output { type filter hook output priority filter; policy accept;
    oifname "lo" accept; oifname <TUN> accept
    meta nfproto != ipv6 accept                      # IPv4 is TP-048's
    meta mark 0x7470 accept                          # links, the direct DNS upstream
    ip6 daddr @exempt6 accept
    icmpv6 type 130-137 accept; icmpv6 type 143 accept   # ND, MLD (an NS to a global target)
    meta l4proto tcp counter reject with tcp reset
    counter reject with icmpx admin-prohibited }
}
```
  Refused, not dropped: TCP connect fails at once with ECONNREFUSED (a drop leaves it retrying SYNs), ICMP and UDP get the ICMPv6 error. Applied in one transaction (add, delete, add the table: never a moment without it); re-applying what is in place only checks the chain, its rule count and the set are there (elements deleted one by one go unnoticed: only refusals could come of it). Only output is guarded: a device forwards nothing of its own, and forwarded packets can't be bound to an interface.
- `internal/dataplane/routetable`: `Guard` (interface) and `GuardFor(Want)` = exactly the table's throws (`Direct` ∪ `Bypass`) and the mark (`guard.go`); the Enforcer applies it after the routes on every Apply and re-apply (`routetable.go` `apply`), its failure is `Status.Error = ErrorGuard` (health `route_table_not_enforced`, retried every `RetryAfter`), Close removes it after the routes, `Clear` removes a crashed run's (the agent already calls `Clear` on a disconnected or failed start: no agent or engine change). `New` takes the OS's guard (`guard_linux.go`; `guard_other.go`: none, the marked macOS stub), `OpenWithGuard` for namespaces; `Open` stays routes-only. The engine's shrink-before/grow-after ordering covers the guard too (shrinking takes routes out first; growing puts routes first, so a new direct destination is refused for the moment between, never leaked).
- `lists.Set.Ranges`: the merged spans (disjoint, never adjacent), what an interval set wants.
- Crash: the table stays with the route table (fail-closed for IPv6, bound sockets included) until the next start; a clean stop or disconnect removes it.

*Gotchas* (also in recall): google/nftables puts a message's set elements in one netlink attribute, whose length is 16 bits: over 64 KiB the kernel answers ENOENT, so elements go 1024 per message (`elementsPerMessage`). `Flush` sends the whole batch in one sendmsg: a country-sized set (~10k IPv6 ranges, 20k elements, ~700 KB) needs SO_SNDBUFFORCE/SO_RCVBUFFORCE (8 MiB), or the send fails and error acks overflow (ENOBUFS). An interval reaching the top address (ff00::/8) has no end element. iputils `ping -m` wants a decimal mark.

*Cost:* 10,090 IPv6 ranges in 36 ms (namespace test); the RU-sized `TestCountrySizedTable`, now with the guard: connect 0.31 s, one endpoint moved 0.14 s, to "everything" 0.29 s, back 0.29 s, disconnect 0.25 s (a shared Docker host).

*Effects worth knowing:* every interface but the TUN and lo counts as physical (rule 5298's set): IPv6 from a bound socket to another VPN's interface, a bridge or a veth is refused unless direct. NetworkManager's per-device IPv6 connectivity check and systemd-resolved's per-link IPv6 DNS fail while connected (that is the point; resolved's per-link domains already make `dns_not_protected`).

**macOS (round 2, after TP-019 merges): what it needs.**
1. `internal/dataplane/firewall/guard_darwin.go`: an `IPv6Guard` with the same `Apply(ctx, Exempt)`, `Close`, and `ClearIPv6Guard`, as a pf anchor under Apple's `com.apple/*` hook (e.g. `com.apple/thinkpol`, loaded with `pfctl -a com.apple/thinkpol -f -`, so `/etc/pf.conf` is never edited), with a persistent table for the exempt destinations (pf tables take prefixes: `Exempt.Direct`'s IPv6 `Prefixes()` plus `firewall.LinkScoped`, loaded with `pfctl -a … -t thinkpol_exempt6 -T replace -f -`):
```
pass out quick on lo0 all
pass out quick on <utunN> all
pass out quick inet6 to <thinkpol_exempt6>
pass out quick inet6 proto icmp6 icmp6-type { 130, 131, 132, 133, 134, 135, 136, 137, 143 }
block return out quick inet6 all
```
   pf must be enabled by reference (`pfctl -E` returns a token; `pfctl -X <token>` releases it), so the guard doesn't turn off a pf someone else enabled, nor leave pf on when it is gone.
2. **No socket mark on macOS:** links and the direct DNS upstream are bound to the physical interface (`IP_BOUND_IF`, TP-019's `ifbind`), not marked. Endpoints are in `Exempt.Direct` already; the direct upstream resolvers are not (on Linux the mark covers them): add them (an `Exempt.Upstreams`, or put them into the Want the guard is built from) or the direct DNS of a device with an IPv6 resolver breaks on macOS.
3. **Records, crash, Clear:** the anchor and the pf token survive a crash (fail-closed, as on Linux). Record the token where TP-019 records routes (`record_darwin.go`'s directory and boot-session header): the next start's `routetable.Clear` flushes the anchor (`pfctl -a com.apple/thinkpol -F all`) and releases a token from the same boot; after a reboot the anchor is gone anyway.
4. `routetable/guard_darwin.go`: `newGuard`/`clearGuard` returning the pf guard (and narrow `guard_other.go`'s build line to `(!linux && !darwin) || android`). With TP-019's split routes, the guard also covers what its Notes leave to pf: foreign host routes over tunneled destinations (IPv6), scoped routing by source address, interface-bound sockets.
5. A darwin unit test for the generated anchor and table text (no pfctl), and **the checklist** on a real Mac, connected with "all but domestic": `ping6 -c1 -I en0 2001:4860:4860::8888` and `curl -6 -m5 --interface en0 https://[2001:4860:4860::8888]/` refused at once; `sudo tcpdump -ni en0 'ip6 and not net fe80::/10 and not net ff00::/8'` shows only direct destinations and entries while browsing; `sudo pfctl -a com.apple/thinkpol -sr` lists the rules; after `sudo pkill -9 -f 'thinkpol up'` the same pings stay refused; `thinkpol up -connect=false` (then stop) leaves the anchor empty and pf's enable count as before (`sudo pfctl -s info`).

## Review findings
Round 1 reviews (design and correctness), orchestrator's list; nothing blocking, all fixed before merge.

- [ ] 1 Watch the guard: subscribe to nftables table/chain deletions (NFNLGRP_NFTABLES) and re-apply through the Enforcer, so `flush ruleset` or `systemctl reload nftables` gets the guard back within about a second, not the 60 s backstop. Test: delete the table from outside, it comes back without an Apply.
- [ ] 2 Adapter composition in the agent (DESIGN.md "Repository layout"): no `routetable/guard_linux.go`/`guard_other.go`; the agent builds `routetable.OpenWithGuard(c, firewall.NewIPv6Guard(), log)` and clears with `errors.Join(routetable.Clear(), firewall.ClearIPv6Guard())`; `routetable.Clear` clears routes only. The Guard port and GuardFor stay in routetable.
- [ ] 3 Android boundary (option b): `Exempt` and `LinkScoped` move to routetable, which never imports firewall; firewall may import routetable. firewall/doc.go, AGENTS.md rule 4 and DESIGN.md's Android line stay true.
- [ ] 4 Lock ordering: Close and Clear remove the guard before letting go of netcfg's owner lock; clearing the guard doesn't depend on `netcfg.New` succeeding; errors joined.
- [ ] 5 `IPv6Guard.Close` retryable: closed only once the table is removed.
- [ ] 6 The guard's own status: `Status.GuardEnforced` and a health code of its own; EOPNOTSUPP/EPROTONOSUPPORT or no nf_tables → terminal `ErrorGuardUnsupported` (no 5 s retries). Decision (orchestrator): without nf_tables connect proceeds and health warns loudly `ipv6_guard_unsupported` (not fail-closed); in DESIGN.md. ErrorGuard's text: "applying the leak guard failed".
- [ ] 7 ND requires `ip6 hoplimit 255` (types 133–137), MLD `ip6 hoplimit 1` (130–132, 143); fix the comment.
- [ ] 8 Honest apply-failure docs: Enforce's comment and the engine's log don't claim all-or-nothing when routes went in and the guard failed.
- [ ] 9 Negative control in the lab test (a capture with the guard off shows ICMPv6 and TCP to the foreign site), or correct the ticket.
- [ ] 10 TP-048 Notes: the kill switch is its own owner (`inet thinkpol-killswitch`, its own exempt4/exempt6, applied by the agent from the toggle and preset, survives disconnect), sharing only Exempt's shape; the IPv6 guard stays the route table's and lives and dies with the connection.
- [ ] 11 macOS round 2 prep: `Exempt.Upstreams []netip.Addr` (pf has no mark), sourced by the agent; the plan uses the firewall's own `<statedir>/pf-guard.token` with a boot-session header (not TP-019's route records: an import cycle); verify the main ruleset has `anchor "com.apple/*"` or fail.
- [ ] 12 Forwarded traffic: narrow the claim to locally generated traffic (rule 5301 confines forwarded traffic); consider a late output priority so a route chain re-marking after us can't slip through (do it if cheap, else note).
- [ ] Nits: `sndbuf` → `sockbuf`; `whole()` counts without a fake set; `Status.Error`'s doc lists every `Error*`.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
- 2026-10-12 docs (TP-057 review): interface-bound sockets are the firewall's to confine
- 2026-10-14 backlog → in-progress — owner: agent-tp-021, branch: tp-021-ipv6-leaks (round 1: Linux; the orchestrator starts it while TP-019 is in review, macOS pf waits for its merge)
- 2026-10-14 Linux: `firewall.IPv6Guard` (nftables `inet thinkpol-guard`), applied with the route table (`routetable.Guard`, `GuardFor`, `OpenWithGuard`), `lists.Set.Ranges`; `TestGatewaysOnLinksAndBoundSockets` flipped for IPv6; lab `TestNoIPv6LeavesAroundTheTunnel`; DESIGN.md "Routing rules and DNS", "IPv6", "Repository layout"; TP-048 Notes; acceptance split into the lab capture (checked) and the macOS checklist (round 2)
- 2026-10-14 in-progress → review — round 1: Linux; macOS pf pending TP-019. `make lint`, `make test`, race on touched packages and `make lab-test LAB_P=2` pass; the macOS checklist box stays open until round 2
- 2026-10-14 review → has-errors — design and correctness reviews: findings 1–12 and nits (see Review findings)
