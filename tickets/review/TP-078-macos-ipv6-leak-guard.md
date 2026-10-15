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
- [x] darwin guard implemented behind the existing `routetable.Guard` port, unit-tested on generated pf rules
- [x] crash cleanup via the pf token record
- [ ] the macOS device checklist (bound `ping6`/`curl -6 --interface en0` refused, tcpdump on en0 clean, still refused after kill -9, clean after `-connect=false`), recorded in Notes

## Notes
**Done in round 1 (2026-10-15), claude-opus-tp078.** The design and its limits are in DESIGN.md, "IPv6", bullet "The leak guard on macOS". Nothing here has touched pf on a real Mac. Every pfctl run goes through `pfctl`, an interface with a stateful fake in the tests (`fakepf_darwin_test.go`). The pfctl output formats the parsers expect come from pfctl(8), pf.conf(5) and the stock `/etc/pf.conf`, and are inferences until the checklist below records the real ones.

- **Code.** `firewall/guard_darwin.go`:
  - `IPv6Guard` with `Apply` :97, `Close` :280 and `Watch` :324 (the poll, every `guardPoll` = 10 s, :20);
  - the hook check :127; the load and its read-back :139; `intact` :180; the enable by reference and takeover :201; `release` :259.
  
  `firewall/pfctl_darwin.go`: the exec runner (15 s bound per run, `LC_ALL=C`, a missing pfctl is `ErrGuardUnsupported`), the parsers, `guardRules`/`anchorText`/`exemptTable`. `firewall/token_darwin.go`: the record `<statedir>/pf-guard.token` (`netcfg.StateDir`), read and written through `trusteddir`. `agent/leakguard_darwin.go`: `newHostGuard`. `leakguard_other.go` is now `(!linux && !darwin) || android`.
- **Deviations from Scope.**
  - The table is loaded with the rules in one `-f -` (a table defined with a list in a ruleset load gets exactly that list, pf.conf(5)), not by a separate `-T replace`. Rules and table then change in one transaction.
  - Close flushes with `-F rules` and `-F Tables`, not `-F all`: for an anchor `-F all` also flushes pf's global state table, info and Sources.
  - The rules carry `inet6` and `no state` (IPv4 decisions stay others'; pf's 10000-state limit).
  - ND passes without a hop-limit match: pf's grammar has none.
  - `Watch` polls the hook, the anchor's rules and table, and pf enabled, not just the rule count.
- **Verified here.**
  - `make lint`, `make test`, and `go test -race` (firewall, agent, routetable) pass on a Mac.
  - A tripwire run of `make test`: the real runner was temporarily made to panic for `/sbin/pfctl`. It never fired, so no test runs pfctl.
  - Linux is unaffected: `make lab-gotest PKG=./internal/dataplane/...` (20 packages; TP-021's guard tests included) and `PKG=./internal/agent/...` (6 packages) pass.
  - Nine hand mutations each failed the tests:
    - release ignoring the pid;
    - `intact` comparing counts only;
    - a record of any boot being held;
    - no takeover of a crashed run's reference;
    - a lost token forgotten;
    - enabling before the load;
    - Close ignoring flush errors;
    - a loose hook match;
    - releasing the old reference before taking a new one when `pfctl -d` leaves references listed.
  - `make test` once failed in `blobs` `TestATricklingPeerIsAbandoned` (timing under load, untouched here); it passed 5/5 alone.
- **Unverified, for the device run.**
  - The stream `pfctl -E` prints `Token : N` on (both are parsed).
  - The `pfctl -s References` line layout (PID first, then the token as a field).
  - Whether `pfctl -a … -F rules` on a missing anchor succeeds.
  - pfctl's listing of the 13 rules.
  - Whether a reload replaces a `const` table's content.
  - Whether `pfctl -d` drops every reference (the guard copes either way: it takes a new reference first, then releases the old one if pf still lists it).
  - Whether bound sockets reach pf at all: TP-019 run 1 saw routing refuse en0-bound sockets with `EHOSTUNREACH`, so step 3 reads the block rule's counter and step 4 forces a route that would leak.
- **For TP-046.** A service started at boot before launchd's `com.apple.pfctl` loads `/etc/pf.conf` finds no hook, and the guard stays unsupported for that connection. Check the order, or re-check after a delay.

**Device checklist (for the owner; root on the Mac, other VPNs off, a network with native IPv6).** It assumes TP-019's step 0 preparation (`bin/thinkpol`, the state dir) and that nothing else on the Mac uses pf (`sudo pfctl -s References` lists nothing, or note what does). Record each step's output here. `R=2001:4860:4860::8888` throughout.

0. *Baseline (read-only).*
   - `ping6 -c1 -I en0 $R` gets a reply. Without IPv6 the checklist can't run.
   - `sudo pfctl -s rules 2>/dev/null | grep -F 'anchor "com.apple/*"'` prints `anchor "com.apple/*" all`; record it. If it is missing, expect `ipv6_guard_unsupported` in step 1 and stop there.
   - `sudo pfctl -s info 2>/dev/null | head -1`: record Enabled or Disabled.
   - `sudo pfctl -s References 2>/dev/null | tee /tmp/tp078-refs-before.txt`: record the layout verbatim.
   - `sudo pfctl -a com.apple -s Anchors 2>/dev/null`: record Apple's siblings.
   - `sudo ls /private/var/db/thinkpol/pf-guard.token` gives "No such file".
1. *Up.* Run `sudo ./bin/thinkpol up -state /private/var/lib/thinkpol -mode device -log-level debug`, then in a second terminal `sudo ./bin/thinkpol rules preset all-but-domestic`.
   - The log has no `applying the leak guard failed` and no `can't hold the leak guard`.
   - `sudo ./bin/thinkpol status` lists neither `ipv6_guard_not_enforced` nor `ipv6_guard_unsupported`.
2. *What pf holds.*
   - `sudo pfctl -a com.apple/thinkpol -s rules 2>/dev/null` lists 13 rules: pass on `lo0`, pass on `utunN`, pass to `<thinkpol_exempt6>`, five ICMPv6 133–137, four 130–132/143, and `block return out quick inet6 all`. Record it verbatim.
   - `sudo pfctl -a com.apple/thinkpol -t thinkpol_exempt6 -T show 2>/dev/null | grep -cE '^ *(fe80::/10|ff02::/16)$'` gives `2`.
   - `sudo pfctl -s info 2>/dev/null | head -1` says Enabled.
   - `sudo pfctl -s References 2>/dev/null` has exactly one line more than the baseline.
   - `sudo cat /private/var/db/thinkpol/pf-guard.token` has `boot <uuid>`, equal to `sysctl -n kern.bootsessionuuid`, and `token <T> pid <P>`, equal to that new line's token and PID.
   - Record `pfctl -E`'s output from the debug log if it is there.
3. *Bound sockets refused.*
   - `sudo pfctl -a com.apple/thinkpol -v -s rules 2>/dev/null | grep -A1 '^block'`: note `Packets:`.
   - `time ping6 -c1 -I en0 $R` gets no reply and returns at once (record its message).
   - `time curl -6 -sS -m5 --interface en0 "https://[$R]/"; echo $?` exits 7 in well under 5 s, not 28; record the message.
   - Repeat the `-v` listing. The block rule's `Packets:` grew if pf refused them. If it didn't, routing refused first (`EHOSTUNREACH`): record which.
   - Same with the en0 source address: `A=$(ifconfig en0 inet6 | awk '/inet6/ && !/fe80/ && !/deprecated/ {print $2; exit}'); time curl -6 -sS -m5 --interface $A "https://[$R]/"` is refused at once.
4. *A route that would leak (the guard's own case).*
   - `GW=$(netstat -rn -f inet6 | awk '$1=="default" && /en0/ {print $2; exit}'); sudo route -n add -inet6 -host $R $GW`, then `route -n get -inet6 $R` shows `interface: en0`.
   - In a second terminal, `sudo tcpdump -ni en0 "ip6 and host $R"`.
   - `time curl -6 -sS -m5 "https://[$R]/"; echo $?` (not bound) exits 7 at once. The tcpdump shows nothing and the block rule's `Packets:` grew.
   - Clean up with `sudo route -n delete -inet6 -host $R`.
5. *What is exempt still works.*
   - `sudo ./bin/thinkpol status` shows the links up.
   - After 2 minutes `ndp -an | grep en0` still has reachable entries (neighbour discovery passes), and `ping6 -c1 fe80::1%en0` (or the router's link-local `$GW`) replies.
   - If the direct set has IPv6, a domestic site with an AAAA record answers over `curl -6`.
   - `sudo pfctl -a com.apple/thinkpol -t thinkpol_exempt6 -T test <its address>` gives `1/1 addresses match`.
6. *Leak capture.* Run `sudo tcpdump -ni en0 'ip6 and not net fe80::/10 and not net ff00::/8'` while browsing tunnelled IPv6 sites for a minute. Only direct destinations, entries and the direct upstream appear; check any surprise with `-T test` as in 5.
7. *Outside changes undone* (the 10 s poll). Each within about 15 s:
   - `sudo pfctl -a com.apple/thinkpol -F rules`: the 13 rules are back.
   - `sudo pfctl -a com.apple/thinkpol -t thinkpol_exempt6 -T add ::/0`: refused (the table is `const`; record the message). If it was taken instead, `-T show` loses `::/0` again.
   - `sudo pfctl -d`: `-s info` says Enabled again, `-s References` has a new token, and the record names it.
   
   After each, `thinkpol status` has no `ipv6_guard_*` problem.
8. *A re-apply with other exempts.* `sudo ./bin/thinkpol rules preset everything`:
   - `-T show | wc -l` changes;
   - `-s References` gets no new line;
   - the health stays clean.
   
   Then `sudo ./bin/thinkpol rules preset all-but-domestic`.
9. *Crash.* `sudo pkill -9 -f 'thinkpol up'`. Step 3's `ping6` and `curl` are still refused at once. The 13 rules, pf Enabled and the record all stay.
10. *Start without connecting clears it.* `sudo ./bin/thinkpol up -state /private/var/lib/thinkpol -mode device -connect=false`, then Ctrl-C after `starting`.
    - The log has no `removing a previous run's routes failed`.
    - `sudo pfctl -a com.apple/thinkpol -s rules 2>/dev/null` lists nothing (or the anchor is gone).
    - `sudo pfctl -a com.apple/thinkpol -t thinkpol_exempt6 -T show` says the table does not exist.
    - `sudo pfctl -s References 2>/dev/null | diff /tmp/tp078-refs-before.txt -` shows only the timestamps differ.
    - `pfctl -s info | head -1` is as in the baseline.
    - The record is gone, and `ping6 -c1 -I en0 $R` replies again.
    - Run step 10 a second time on the now clean host: the log is still clean (a fresh guard's Close with nothing to remove).
11. *Takeover and clean stop.*
    - Connect (as 1), kill -9 (as 9), connect again (as 1). `-s References` has exactly one line more than the baseline.
    - Ctrl-C. Everything is as in step 10's checks.
12. *No hook (optional; touches the main ruleset, restored at the end).*
    - While connected, `echo 'pass all' | sudo pfctl -f -` (replaces Apple's main ruleset). Within about 15 s `thinkpol status` shows `ipv6_guard_unsupported`.
    - Restore with `sudo pfctl -f /etc/pf.conf` and check that step 0's grep matches again.
    - `sudo ./bin/thinkpol disconnect; sudo ./bin/thinkpol connect`: the health is clean.

*Rollback, at any point:*
- `sudo pfctl -a com.apple/thinkpol -F rules; sudo pfctl -a com.apple/thinkpol -F Tables`;
- `sudo pfctl -X <token from /private/var/db/thinkpol/pf-guard.token>`, then remove the record;
- `sudo pfctl -f /etc/pf.conf` if step 12 was left half done.

A reboot undoes all of it: the anchor and the reference go, and the record's boot session no longer matches.

## Log
- 2026-10-15 created in backlog (split from TP-021 after 3 review rounds; the Linux guard merged in TP-021)
- 2026-10-15 backlog → in-progress — owner: claude-opus-tp078
- 2026-10-15 in-progress → review — round 1: pf guard (anchor com.apple/thinkpol, table thinkpol_exempt6, enable by reference with a boot-stamped token record, 10 s poll), agent wiring, DESIGN "IPv6". make lint, make test (with a pfctl tripwire: no test runs pfctl), go test -race (firewall, agent, routetable), lab-gotest dataplane and agent pass; nine mutations each caught. Device checklist pending (owner's run after review round 1); pfctl output formats and pf behaviour are inferences from the man pages until then
