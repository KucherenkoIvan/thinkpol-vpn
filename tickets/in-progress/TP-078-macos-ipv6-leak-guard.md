---
id: TP-078
title: "IPv6 leak guard on macOS (pf)"
milestone: M1
area: dataplane/firewall
repo: thinkpol-vpn
size: M
depends_on: [TP-019, TP-021]
refs: [D6, DESIGN#ipv6]
needs_human: macos
owner: "claude-opus-tp078"
branch: "tp-078-macos-pf-guard"
---

## Goal
On macOS, interface-bound sockets cannot send IPv6 around the tunnel while connected, using the same rules as TP-021's Linux guard.

## Scope
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
2. **No socket mark on macOS:** links and the direct DNS upstream are bound to the physical interface (`IP_BOUND_IF`, TP-019's `ifbind`), not marked. Endpoints are in `Exempt.Direct`; the direct upstreams come in `Exempt.Upstreams`, which `routetable.GuardFor` fills from `Want.Upstreams`, the same source as TP-019's scoped upstream routes (the agent's `Engine.SetDirectUpstreams`, from the resolver's upstreams and the system's when they change); a change re-applies routes and guard together.
3. **Records, crash, Clear:** the anchor and the pf token survive a crash (fail-closed, as on Linux). The firewall keeps its own record, `<statedir>/pf-guard.token`, with a boot-session header (as TP-019's records have, but its own file: using TP-019's netcfg records from `firewall` would make an import cycle); a fresh guard's `Close` (what `routetable.Clear` calls) flushes the anchor (`pfctl -a com.apple/thinkpol -F all`) and releases a token from the same boot; after a reboot the anchor is gone anyway and the record is dropped.
4. `agent/leakguard_darwin.go`: `newHostGuard` returning the pf guard (and narrow `leakguard_other.go`'s build line to `(!linux && !darwin) || android`). With TP-019's split routes, the guard also covers what its Notes leave to pf: foreign host routes over tunneled destinations (IPv6), scoped routing by source address, interface-bound sockets. `Watch`: pf has no event stream; poll the anchor's rule count (or rely on the backstop) and say so.
5. A darwin unit test for the generated anchor and table text (no pfctl), and **the checklist** on a real Mac, connected with "all but domestic": `ping6 -c1 -I en0 2001:4860:4860::8888` and `curl -6 -m5 --interface en0 https://[2001:4860:4860::8888]/` refused at once; `sudo tcpdump -ni en0 'ip6 and not net fe80::/10 and not net ff00::/8'` shows only direct destinations, entries and the direct upstream while browsing; `sudo pfctl -a com.apple/thinkpol -sr` lists the rules; after `sudo pkill -9 -f 'thinkpol up'` the same pings stay refused; `thinkpol up -connect=false` (then stop) leaves the anchor empty and pf's enable count as before (`sudo pfctl -s info`).

From TP-021 review item 11 (macOS round 2 prep): the plan uses the firewall's own `<statedir>/pf-guard.token` with a boot-session header (not TP-019's route records: an import cycle); verify the main ruleset has `anchor "com.apple/*"` or fail; `Exempt.Upstreams` (`routetable/guard.go`), filled from the resolver's direct upstreams (since TP-019's merge of TP-021: `GuardFor` takes them from `Want.Upstreams`, and the agent's `leakGuard` wrapper is gone).

## Out of scope
Linux nftables guard (TP-021).

## Acceptance
- [ ] darwin guard implemented behind the existing `routetable.Guard` port, unit-tested on generated pf rules
- [ ] crash cleanup via the pf token record
- [ ] the macOS device checklist (bound `ping6`/`curl -6 --interface en0` refused, tcpdump on en0 clean, still refused after kill -9, clean after `-connect=false`), recorded in Notes

## Notes

## Log
- 2026-10-15 created in backlog (split from TP-021 after 3 review rounds; the Linux guard merged in TP-021)
- 2026-10-15 backlog → in-progress — owner: claude-opus-tp078
