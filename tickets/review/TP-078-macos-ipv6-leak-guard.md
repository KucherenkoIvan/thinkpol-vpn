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
1. `internal/dataplane/firewall/guard_darwin.go`: a pf guard implementing `routetable.Guard` (`Apply(ctx, Exempt)`, `Watch`, `Close`), as an anchor under Apple's `com.apple/*` hook (`com.apple/000.thinkpol`, renamed from `com.apple/thinkpol` in round 2 (R2.4) so it sorts first, loaded with `pfctl -a com.apple/000.thinkpol -f -`, so `/etc/pf.conf` is never edited). **First verify the main ruleset references `anchor "com.apple/*"`** (`pfctl -s rules` / `-s Anchors`) **or fail** with `ErrGuardUnsupported`-like status: an anchor nothing evaluates guards nothing. A persistent table holds the exempt destinations (pf tables take prefixes: `Exempt.Direct`'s IPv6 `Prefixes()`, `Exempt.Upstreams`, plus `routetable.LinkScoped`; `pfctl -a … -t thinkpol_exempt6 -T replace -f -`):
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
3. **Records, crash, Clear:** the anchor and the pf token survive a crash (fail-closed, as on Linux). The firewall keeps its own record, `<statedir>/pf-guard.token`, with a boot-session header (as TP-019's records have, but its own file: using TP-019's netcfg records from `firewall` would make an import cycle); a fresh guard's `Close` (what `routetable.Clear` calls) flushes the anchor (`pfctl -a com.apple/000.thinkpol -F all`) and releases a token from the same boot; after a reboot the anchor is gone anyway and the record is dropped.
4. `agent/leakguard_darwin.go`: `newHostGuard` returning the pf guard (and narrow `leakguard_other.go`'s build line to `(!linux && !darwin) || android`). With TP-019's split routes, the guard also covers what its Notes leave to pf: foreign host routes over tunneled destinations (IPv6), scoped routing by source address, interface-bound sockets. `Watch`: pf has no event stream; poll the anchor's rule count (or rely on the backstop) and say so.
5. A darwin unit test for the generated anchor and table text (no pfctl), and **the checklist** on a real Mac, connected with "all but domestic": `ping6 -c1 -I en0 2001:4860:4860::8888` and `curl -6 -m5 --interface en0 https://[2001:4860:4860::8888]/` refused at once; `sudo tcpdump -ni en0 'ip6 and not net fe80::/10 and not net ff00::/8'` shows only direct destinations, entries and the direct upstream while browsing; `sudo pfctl -a com.apple/000.thinkpol -sr` lists the rules; after `sudo pkill -9 -f 'thinkpol up'` the same pings stay refused; `thinkpol up -connect=false` (then stop) leaves the anchor empty and pf's enable count as before (`sudo pfctl -s info`).

From TP-021 review item 11 (macOS round 2 prep): the plan uses the firewall's own `<statedir>/pf-guard.token` with a boot-session header (not TP-019's route records: an import cycle); verify the main ruleset has `anchor "com.apple/*"` or fail; `Exempt.Upstreams` (`routetable/guard.go`), filled from the resolver's direct upstreams (since TP-019's merge of TP-021: `GuardFor` takes them from `Want.Upstreams`, and the agent's `leakGuard` wrapper is gone).

## Out of scope
Linux nftables guard (TP-021).

## Acceptance
- [x] darwin guard implemented behind the existing `routetable.Guard` port, unit-tested on generated pf rules
- [x] crash cleanup via the pf token record
- [x] on a real Mac the guard loads, verifies its rules and is enforced (health without `ipv6_guard_*`), with TP-092's fix (device sessions A and B, 2026-10-16, in Notes)
- [ ] (moved to TP-096) the native-IPv6 device steps: bound `ping6`/`curl -6 --interface en0` refused, tcpdump on en0 clean, still refused after kill -9, clean after `-connect=false`

## Notes
**Round 1 (2026-10-15), claude-opus-tp078; round 2 the same day after the cross-family review (Review findings below).** The design and its limits are in DESIGN.md, "IPv6", bullet "The leak guard on macOS". Nothing here has touched pf on a real Mac: every pfctl run goes through `pfctl`, an interface with a stateful fake in the tests (`fakepf_darwin_test.go`: anchors, tables, references, states and `-k` as XNU's DIOCKILLSTATES matches them, `const` tables refusing an in-place change, `Invalid argument` for a missing anchor, an unreadable References layout). The pfctl output formats are from pfctl(8), pf.conf(5), the stock `/etc/pf.conf` and the published OS X `-s References` transcripts the review cites; the rest is inference until the checklist below records them.

- **Code.**
  - `firewall/guard_darwin.go`: `IPv6Guard`: `Apply` :139, `Close` :487, `Watch` :545 (polls every `guardPoll` = 10 s, :21; `broken` :576).
  - The steps of an Apply: the hook check :187, the load and its read-back :202, `intact` :254, `enable` (reference taken, taken over, or found by pid) :308, `kill` (states) :403.
  - Releasing and clearing: `resolve` (a token by pid) :289, `release` :380, `flush` (a missing anchor counts as empty) :454.
  - `firewall/pfctl_darwin.go`: the exec runner :63 (15 s bound, `LC_ALL=C`; a missing pfctl is `ErrGuardUnsupported`) and the parsers: `hooked` :148, `parseToken` :172, `parseReferences` :221, `parseTable` :282, `parseStateAddrs` :317. Also `exemptPrefixes` :342, `upstreamTargets` :362, `guardRules` :409, `anchorText` :441, `saneRules` :463.
  - `firewall/token_darwin.go`: the record `<statedir>/pf-guard.token` (`netcfg.StateDir`): `boot <uuid>` plus `token <value|unknown> pid <pid>`, read and written through `trusteddir`.
  - `agent/leakguard_darwin.go`: `newHostGuard`. `leakguard_other.go` is now `(!linux && !darwin) || android`.
  - Round 2 also carries the upstreams' ports. `routetable.Want.Upstreams` and `Exempt.Upstreams` are `[]netip.AddrPort`, so are `Engine.SetDirectUpstreams` and the agent's runner (a configured `-dns-upstream [v6]:port` keeps its port).
- **Deviations from Scope.**
  - The table goes in with the rules in one `-f -`, not by `-T replace`: one transaction. It is not `const` (R2.8).
  - Close runs `-F rules` and `-F Tables`, never `-F all`, which also flushes pf's global state table.
  - Rules are `inet6` and `no state`.
  - Neighbour discovery has no rule: the exempt table's link-local unicast and multicast cover it (R2.2). MLD goes to `ff00::/8`; no hop-limit match exists in pf.
  - Each global IPv6 DNS upstream gets DNS on its own port and ICMPv6 135/136 (R2.3, R3.3), by rules naming it; round 2's upstream table is gone. A link-local upstream is passed whole by `fe80::/10`.
  - The anchor is `com.apple/000.thinkpol` (R2.4).
  - Watch polls the hook, the rules, the table, pf enabled, and a failed last Apply.
- **Pid reuse (R2.7).** The record names the reference by the token and by the pid of the pfctl that ran `-E`. That pfctl exits at once. A later enabler can get the same pid, and a released token value can come back (it is a kernel address's hash). If both happen to one reference, `-X` would release someone else's. pf offers nothing better to tell them apart. The window is a released-and-retaken token plus a wrapped pid within one boot.
- **Verified here** (rounds 2 and 3).
  - `make lint`, `make test`, and `go test -race` (firewall ×3, agent, routetable, dataplane) pass on a Mac.
  - The pfctl tripwire was rerun each round: no test runs `/sbin/pfctl`.
  - The lab passes: `lab-gotest` for `./internal/dataplane/...` and `./internal/agent/...` (Linux; the upstream-type change touches it).
  - Planted bugs, each failing the tests: 17 in round 2, 4 in round 3 (listed in the Log lines).
- **Unverified, for the device run.**
  - The stream `pfctl -E` prints its token on.
  - pfctl's listing of the rules (expansion, `no state` kept).
  - What a flush or listing of a missing anchor answers.
  - The `-s states` layout, whether `-k` of nothing exits 0, and whether `-k <local> -k <remote>` kills an inbound state the other way round (step 0 records the first two).
  - Whether a reload replaces a table's content (step 8 decides).
  - Whether bound sockets reach pf at all (steps 3–4).
  - Whether `pfctl -d` drops references (step 7, only on a Mac where nothing else holds one).
- **For TP-046.** A service started at boot before launchd's `com.apple.pfctl` loads `/etc/pf.conf` finds no hook (unsupported for that connection).

**Device checklist (for the owner; root on the Mac, other VPNs off, a network with native IPv6).**

Safe on a daily Mac whose Application Firewall holds a pf reference. Nothing here disables pf or replaces the main ruleset unless step 0 shows nothing else uses them; every step that adds something removes it in the same command line.

It assumes TP-019's step 0 preparation (`bin/thinkpol`, the state dir). Record each step's output here. `R=2001:4860:4860::8888` throughout.

0. *Baseline (read-only).*
   - `ping6 -c1 -I en0 $R` replies. Without IPv6 the checklist can't run.
   - `sudo pfctl -s rules 2>/dev/null | tee /tmp/tp078-main-before.txt` lists `anchor "com.apple/*" all` with no `pass ... quick` line above it. Record it verbatim; without the line, expect `ipv6_guard_unsupported` at step 1 and stop there.
   - `sudo pfctl -s info 2>/dev/null | head -1 | tee /tmp/tp078-info-before.txt`.
   - `sudo pfctl -s References 2>/dev/null | tee /tmp/tp078-refs-before.txt`: record the layout verbatim. **Note whether any reference is listed below the header** (the Application Firewall's `socketfilterfw`, another app): if one is, step 7's `pfctl -d` and step 12 are skipped.
   - `sudo pfctl -a com.apple -s Anchors 2>/dev/null`: Apple's anchors there.
   - `sudo pfctl -ss 2>/dev/null | tee /tmp/tp078-states-before.txt | grep -c '\['` counts the IPv6 states. Record one IPv6 line verbatim: `grep -m1 '\[' /tmp/tp078-states-before.txt`. If pf is off and holds no state, take one after step 1 instead.
     - The guard expects lines like `ALL tcp 2001:db8::10[51000] -> 2001:db8:ab::7[443] ESTABLISHED:ESTABLISHED`: each IPv6 address with its port in brackets, a translation in parentheses, `->` or `<-`.
     - IPv6 addresses printed another way mean the guard finds no state to kill: states opened before `up` would survive. Record it and flag it.
   - One throwaway kill, of two documentation addresses no real flow can have: `sudo pfctl -k 2001:db8::1 -k 2001:db8::2; echo "exit $?"`.
     - Exit 0, with a line like `killed 0 states`, means the guard's kills work.
     - A non-zero exit or a usage message means every Apply that finds a state to kill fails, and the health says `ipv6_guard_not_enforced` while such states exist. Record the output and flag it.
   - `sudo ls /private/var/db/thinkpol/pf-guard.token` gives "No such file".
1. *Up, with a connection open from before.* (If `$R` turns out to be one of the direct DNS upstreams, step 2's rules name it: use `R=2606:4700:4700::1111` instead.)
   - In a second terminal, `sudo tcpdump -ni en0 "ip6 and host $R"`.
   - In a third, `nc -6 $R 443` (an IPv6 TCP connection, left open; tcpdump shows its handshake).
   - Then `sudo ./bin/thinkpol up -state /private/var/lib/thinkpol -mode device -log-level debug`, and `sudo ./bin/thinkpol rules preset all-but-domestic`.
   - The log has no `applying the leak guard failed` and no `can't hold the leak guard`.
   - `sudo ./bin/thinkpol status` lists neither `ipv6_guard_not_enforced` nor `ipv6_guard_unsupported`.
   - `sudo pfctl -ss 2>/dev/null | grep -F "$R"` prints nothing: a state to `$R` from before is killed.
   - Type a line into `nc`: tcpdump shows nothing more from the host to `$R` on en0. A packet there is a fail.
   - Close nc and tcpdump.
2. *What pf holds.*
   - `sudo pfctl -a com.apple/000.thinkpol -s rules 2>/dev/null` lists, in order:
     - pass on `lo0`, pass on `utunN`, pass to `<thinkpol_exempt6>`;
     - for each global IPv6 direct upstream, `proto tcp` and `proto udp` to that address on its own port (`port = 53`), and no other port;
     - for each such address, two ICMPv6 neighbour rules (`neighbrsol`, `neighbradv`): only an on-link upstream needs them;
     - four MLD rules to `ff00::/8`;
     - `block return out quick inet6 all`.
     
     That is 12 rules with one global IPv6 upstream on one port, and 8 with none (a link-local upstream adds none: `fe80::/10` passes it). **Every pass line ends in `no state`, and the block has `quick`**; anything else is a fail. Record the listing verbatim.
   - `sudo pfctl -a com.apple/000.thinkpol -t thinkpol_exempt6 -T show 2>/dev/null | grep -cE '^ *(fe80::/10|ff02::/16)$'` gives `2`.
   - The upstream rules name exactly the global IPv6 direct upstreams (`scutil --dns`'s resolver #1 IPv6 addresses, or the configured ones).
   - `sudo pfctl -a com.apple -s Anchors 2>/dev/null` lists `com.apple/000.thinkpol`. pf evaluates the anchors by name, whatever order this listing prints them in.
   - `sudo pfctl -s info 2>/dev/null | head -1` says Enabled.
   - `sudo pfctl -s References 2>/dev/null` has exactly one line more than the baseline, process `pfctl`.
   - `sudo cat /private/var/db/thinkpol/pf-guard.token` has `boot <uuid>`, equal to `sysctl -n kern.bootsessionuuid`, and `token <T> pid <P>`, equal to that new line. `token unknown` there is a fail: record the `-E` output in the log.
3. *Bound sockets refused by pf.*
   - `sudo pfctl -a com.apple/000.thinkpol -v -s rules 2>/dev/null | grep -A1 '^block'`: note `Packets:`.
   - `time ping6 -c1 -I en0 $R` gets no reply and returns at once.
   - `time curl -6 -sS -m5 --interface en0 "https://[$R]/"; echo $?` exits 7 in well under 5 s, not 28.
   - `A=$(ifconfig en0 inet6 | awk '/inet6/ && !/fe80/ && !/deprecated/ {print $2; exit}'); time curl -6 -sS -m5 --interface $A "https://[$R]/"` is refused at once.
   - Repeat the `-v` listing. If `Packets:` didn't grow, routing refused first and this step says nothing about the guard. Growth is only suggestive, because background IPv6 to destinations that aren't exempt counts too. Record the messages either way: **step 4 decides**.
4. *A route that would leak.* One command line; it adds the route, tests, and removes it whatever happens:
   - Find the gateway: `GW=$(netstat -rn -f inet6 | awk '$1=="default" && /en0/ {print $2; exit}'); echo $GW`.
   - In a second terminal, `sudo tcpdump -ni en0 "ip6 and host $R"`.
   - Then run: `sudo route -n add -inet6 -host $R $GW; route -n get -inet6 $R | grep interface; time curl -6 -sS -m5 "https://[$R]/"; echo "curl exit $?"; sudo route -n delete -inet6 -host $R`.
   - Expect `interface: en0`, then curl exit 7 at once, and tcpdump showing nothing.
   - **This step decides the guard's case.** The route sends `$R` out of en0, so without the guard the curl would leave there (TP-021's lab test shows the same with the guard off); only pf can stop it.
   - `netstat -rn -f inet6 | grep -F "$R"` is empty afterwards.
5. *What is exempt still works, and only that.*
   - `sudo ./bin/thinkpol status` shows the links up.
   - After 2 minutes, `ndp -an | grep en0` still has reachable entries (neighbour discovery passes), and `ping6 -c1 $GW` replies.
   - With an IPv6 direct upstream `U` and en0's address `A` (step 3): `dig -b $A @$U example.com +short +time=3` answers (DNS to it is exempt).
   - **Only if `U` is global** (not `fe80::…`): `time curl -6 -sS -m5 --interface en0 "http://[$U]/"` is refused at once (nothing else to it is). A link-local `U` is passed whole by the exempt table's `fe80::/10`, by design (it never leaves the link), so there the curl proves nothing.
   - If the direct set has IPv6, a domestic site with an AAAA record answers over `curl -6`, and `sudo pfctl -a com.apple/000.thinkpol -t thinkpol_exempt6 -T test <its address>` gives `1/1 addresses match`.
6. *Leak capture.* Run `sudo tcpdump -ni en0 'ip6 and not net fe80::/10 and not net ff00::/8'` while browsing tunnelled IPv6 sites for a minute. Only direct destinations, entries and DNS to the direct upstream appear; check any surprise with `-T test` as in 5.
7. *Outside changes undone* (the 10 s poll). Each within about 15 s:
   - `sudo pfctl -a com.apple/000.thinkpol -F rules`: the rules are back, the same listing as step 2.
   - `sudo pfctl -a com.apple/000.thinkpol -t thinkpol_exempt6 -T add ::/0` is accepted (the tables aren't `const`). Within about 15 s, `... -T show | grep -c '^ *::/0$'` gives `0`.
   - **Only if step 0 listed no reference** (never on a Mac where the Application Firewall or anything else holds one; that is a hard stop): `sudo pfctl -d`. Then `-s info` says Enabled again, `-s References` lists one new `pfctl` reference, the record names it, and step 1's state check still holds.
   
   After each, `thinkpol status` has no `ipv6_guard_*` problem.
8. *A re-apply with other exempts (decides whether a reload replaces a table).*
   - `sudo pfctl -a com.apple/000.thinkpol -t thinkpol_exempt6 -T show 2>/dev/null > /tmp/tp078-wide.txt`.
   - `sudo ./bin/thinkpol rules preset everything`. Then `-T show` lists fewer entries, and a domestic prefix of `/tmp/tp078-wide.txt` is gone. The log has no `applying the leak guard failed` and the health is clean; `-s References` gets no new line.
   - Then `sudo ./bin/thinkpol rules preset all-but-domestic`: the list equals `/tmp/tp078-wide.txt` again.
   - A table that kept the wide list is a fail. Record the log.
9. *Crash.* `sudo pkill -9 -f 'thinkpol up'`. Step 3's `ping6` and `curl` are still refused at once. The rules, pf Enabled and the record all stay.
10. *Start without connecting clears it.* `sudo ./bin/thinkpol up -state /private/var/lib/thinkpol -mode device -connect=false`, then Ctrl-C after `starting`.
    - The log has no `removing a previous run's routes failed`.
    - `sudo pfctl -a com.apple/000.thinkpol -s rules 2>/dev/null` lists nothing (or the anchor is gone), and `-t thinkpol_exempt6 -T show` says the table doesn't exist.
    - `diff <(sudo pfctl -s References 2>/dev/null | awk 'NR>2 {print $1, $2, $3}') <(awk 'NR>2 {print $1, $2, $3}' /tmp/tp078-refs-before.txt)` is empty: the same references as the baseline, timestamps aside.
    - `sudo pfctl -s info 2>/dev/null | head -1 | awk '{print $2}'` is as in `/tmp/tp078-info-before.txt`.
    - The record is gone, and `ping6 -c1 -I en0 $R` replies again.
    - Run step 10 again on the now clean host: the log is still clean (a fresh guard's Close with nothing there).
11. *Takeover and clean stop.*
    - Connect (as 1, without nc), kill -9 (as 9), connect again (as 1). `-s References` has exactly one line more than the baseline.
    - Ctrl-C. Step 10's checks pass, the References diff included.
12. *No hook, a bypassing hook (optional).* Only if step 0 listed no reference and `/tmp/tp078-main-before.txt` is exactly the stock two lines (no anchor a system service inserted).
    - While connected, run each command line below as one; it restores the main ruleset in the same root shell:
      - `sudo sh -c 'printf "pass out quick inet6 all no state\nanchor \"com.apple/*\" all\n" | pfctl -f - 2>/dev/null; sleep 20; ./bin/thinkpol status | grep -o "ipv6_guard_[a-z_]*"; pfctl -f /etc/pf.conf 2>/dev/null'` prints `ipv6_guard_not_enforced`.
      - `sudo sh -c 'printf "pass all\n" | pfctl -f - 2>/dev/null; sleep 20; ./bin/thinkpol status | grep -o "ipv6_guard_[a-z_]*"; pfctl -f /etc/pf.conf 2>/dev/null'` prints `ipv6_guard_unsupported`.
    - Then `sudo pfctl -s rules 2>/dev/null | diff /tmp/tp078-main-before.txt -` is empty, and `sudo ./bin/thinkpol disconnect; sudo ./bin/thinkpol connect` brings the health back clean.

*Rollback, at any point.*

Stop thinkpol first (Ctrl-C, or `sudo pkill -TERM -f 'thinkpol up'`): while it runs, the guard puts back whatever is flushed within about 10 s. Step 10 (`up -connect=false`, then Ctrl-C) is the clean way to remove everything. After a kill -9 the commands below remove the guard, but the route table's split and reject routes stay (IPv6 refused but for direct destinations) until step 10 runs.

- `sudo route -n delete -inet6 -host 2001:4860:4860::8888` (step 4, if it stopped halfway).
- `sudo pfctl -f /etc/pf.conf` (step 12, if it stopped halfway).
- `sudo pfctl -a com.apple/000.thinkpol -F rules; sudo pfctl -a com.apple/000.thinkpol -F Tables`.
- `sudo pfctl -X <token from /private/var/db/thinkpol/pf-guard.token>` (if it says `unknown`, the `pfctl` line of `pfctl -s References` with that pid), then `sudo rm /private/var/db/thinkpol/pf-guard.token`.

A reboot undoes all of it but the record, whose boot session then no longer matches.

**Device sessions (2026-10-16), the owner's Mac, macOS, a network without native IPv6.**
- Session A (build ebc225f): the guard never came up. pfctl listed the anchor's rules in another order (the ff00::/8 multicast rule first), so `saneRules` refused every load, and health was `ipv6_guard_not_enforced` from the start. The agent logged one WARN, then went quiet. Fixed in TP-092: the load runs with pfctl's optimizer off (`-o none`), and failures warn at most once a minute.
- Session B (TP-092's build): health had no problem from the start, and no guard failure was logged. The guard loaded, its rules passed `saneRules`, and it was enforced. Checks 08, 09 and 10 were UNKNOWN because the network had no native IPv6 (no global address, no IPv6 default route), so the leak paths couldn't be exercised. They move to TP-096.
- After session A's stop, `pfctl -s Anchors` still listed `com.apple/000.thinkpol`, but the anchor held no rules and no tables: pf keeps a flushed anchor's name. No leftover. The pf `-E` token record was absent.
- Seen on the device: when `saneRules` refuses a load, the rules just loaded stay in the anchor (load returns before any flush), and the agent reports not enforced. Follow-up in TP-095.

## Review findings
Cross-family adversarial review (Grok, 2026-10-15) of round 1; orchestrator's list, round 2 of at most 3.

- [x] R2.1 (blocker) An unreadable `pfctl -E` token: the retry returns nil while `lostToken` is set, nothing on disk names the reference, and Close sets `closed` without releasing it (pf stays on after a clean stop). A reference that isn't on disk is a failed Apply, retries included: keep the `-E` pid, recover the token from `-s References` by that pid, keep failing while that fails; Close must not close while it is unresolved. Rewrite `TestAnUnreadableTokenIsNotTakenTwice` to require the reference recorded or released and Close to clean it up.
- [x] R2.2 ND/MLD pass rules match any destination (ICMPv6 133–137/130–132/143 to a global address leaves en0): restrict to `to { fe80::/10, ff00::/8 }` or delete what the exempt table already covers; say why in DESIGN.
- [x] R2.3 The DNS upstream's address is exempt for every socket and protocol: a table of its own, `thinkpol_upstream6`, passing only `proto { tcp, udp }` to its DNS port (853 only if the resolver does DoT); endpoints stay in the main table.
- [x] R2.4 The hook check passes when a `pass ... quick` above `anchor "com.apple/*"` ends evaluation first: fail it then; rename the anchor to sort first among com.apple's children (`com.apple/000.thinkpol`); ticket, DESIGN and checklist follow.
- [x] R2.5 Pre-existing states skip the anchor (floating state policy): after a load pf enforces, kill IPv6 states whose remote is outside the exempt tables (`pfctl -k`), leaving exempt ones and all IPv4 alone; the fake models `-k`.
- [x] R2.6 Device checklist: step 3 fails if the block counter didn't grow; step 4's host route deleted in the rollback; step 7 never runs `pfctl -d` when step 0 listed references (hard stop), References must match the baseline after the run; step 12 optional, restore in the same shell; step 2 requires `no state` on passes and `quick` on the block; `pfctl -ss` before and after connect. Safe on a daily Mac whose Application Firewall holds a pf reference.
- [x] R2.7 Nits: `saneRules` requires `no state` on every pass line; the pid-reuse caveat in the ticket; Watch signals while the last Apply failed (or say why the Enforcer's retry covers it); parser hardening (References line `^(\d+)\s+\S+\s+(\d+)\s+`, ALTQ lines skipped everywhere).
- [x] R2.8 Suspicions: `const` may refuse the reload that repair and preset changes depend on (drop it, or make the checklist decisive; explain); a flush or listing of a missing anchor answering `Invalid argument` is an empty anchor, and the fake can answer so.

Resolution (round 2):
- R2.1 `enable` (`guard_darwin.go:314`): when `-E`'s output has no readable token, the reference is looked up in `-s References` by that pfctl's pid (`resolve` :295, `byPid`). The record is written at once, as `token unknown pid P` if the lookup fails, and Apply returns `errUnreadToken`. Every retry looks again: it neither succeeds nor takes a second reference until the token is found, or until a readable listing shows that pid has no reference left.
  - `Close` (:492) resolves the same way and stays open (record kept) while it can't. A fresh guard's Close resolves a crashed run's `unknown` record.
  - `lostToken` is gone.
  - Test: `TestAnUnreadableTokenIsNotTakenTwice` has four subtests: found by pid (recorded, Close releases, pf off); not found yet (Apply fails twice with one reference, the record names the pid, Close fails and keeps both, then succeeds once the listing is readable); a crashed run's (a fresh Close releases it); gone meanwhile.
- R2.2 The neighbour-discovery rule is gone: the exempt table's `fe80::/10` and `ff02::/16` are every ND destination; ND to a global address leaves only if that address is exempt. MLD passes only `to ff00::/8` (`guardRules`, `pfctl_darwin.go:417`). DESIGN says why, and what is left: no hop-limit match, so MLD-typed ICMPv6 reaches any multicast group.
- R2.3 `thinkpol_upstream6` (`upstreamPrefixes`/`upstreamPorts` :362–372) holds the IPv6 direct upstreams, passing only `proto { tcp, udp }` to their ports, plus neighbour solicitations and advertisements (135, 136) so an on-link upstream's unicast probes work.
  - The resolver does no DoT (plain DNS, UDP then TCP), so no 853.
  - Ports aren't always 53: `-dns-upstream` takes `IP:port`. So `Want.Upstreams`/`Exempt.Upstreams` became `[]netip.AddrPort` (`routetable.go:78`, `guard.go:61`, `upstreams`/`upstreamAddrs`), as did `Engine.SetDirectUpstreams` and the agent's runner. Linux still ignores them.
  - Tests: `TestTheTables`, `TestAnchorText`, `TestApplyingAnotherExemptReplacesIt` (a `:5353` upstream), routetable `exempt_test` (another port isn't equal), agent `TestAConfiguredUpstreamReachesTheRouteTableWithItsPort`.
- R2.4 `hooked` (:149) returns `hookBypassed` when a `pass` with `quick` that could match outgoing IPv6 (not `in` only, not `inet` only) comes before the hook line. `checkHook` (:184) makes that an ordinary failure (`ipv6_guard_not_enforced`, retried; the condition can go away), while a missing hook stays unsupported. `Watch` polls it.
  - The anchor is `com.apple/000.thinkpol` (`GuardAnchor`), before `200.AirDrop` and `250.ApplicationFirewall`.
  - Tests: `TestHooked` (11 cases), `TestAQuickPassAboveTheHookIsNotEnforced`, `TestWatchSignalsWhenTheGuardBreaks`.
- R2.5 `kill` (:406) runs after a load or an enable. It reads `pfctl -s states` (`parseStateAddrs`, order-independent), tells the host's end by its interface addresses, and for each IPv6 state whose other end the tables don't exempt runs `pfctl -k <local> -k <remote>` and `-k <remote> -k <local>`. pfctl(8): "kill all the state entries from host1 to host2"; XNU matches the source as the side that opened the state, so the two calls cover both directions without a wildcard.
  - Exempt, loopback and IPv4 states are left alone. A failed kill fails the Apply, and the retry kills.
  - The fake models DIOCKILLSTATES. Test: `TestApplyKillsStatesTheGuardRefuses`: an outbound and an inbound foreign state killed; direct, upstream, link-local multicast, loopback and IPv4 states kept; a state made while pf was off killed on re-enable; a re-apply kills nothing; a failed kill retried.
- R2.6 The checklist above:
  - step 0 records References and gates steps 7 and 12 on them (a hard stop when anything else holds a reference);
  - step 1 opens a connection before `up` and checks `pfctl -ss`;
  - step 2 requires `no state` and `quick`;
  - step 3 fails when the counter didn't grow;
  - step 4 adds and deletes its route on one command line, and the rollback deletes it too;
  - step 10 diffs References against the baseline;
  - step 12 restores in the same root shell.
- R2.7 Nits:
  - `saneRules` requires ` no state ` on every pass (:475; `TestSaneRules`, `TestALoadPfDoesntHoldFails`).
  - The pid-reuse caveat is in Notes.
  - `Watch` signals while the last Apply failed (`broken` :581, `failing`), so a retry is due even if the Enforcer's own stops; tested.
  - References lines match `^(\d+)\s+\S+\s+(\d+)\s+` (`parseReferences` :222, with the review's transcripts in `TestParseReferences`).
  - `lines` drops ALTQ lines for every parser.
- R2.8 Suspicions:
  - `const` dropped. A reload that can't narrow a const table would leave a wide preset's exemptions behind, which is worse than a `-T add` the 10 s poll undoes. The fake models OpenBSD's refusal, and `TestApplyingAnotherExemptReplacesIt` fails with `const` back. Step 8 checks the reload on the device.
  - A flush or listing of a missing anchor that answers `Invalid argument` is empty (`flush` :457, `listRules` :228), but only once a listing confirms nothing is there. Tests: `TestAFreshGuardCloseOnACleanHost` (both answers), `TestAFlushThatFailsIsNoEmptyAnchor`.

### Round 3 (Grok delta review of round 2, 2026-10-15)
Status: R2.1–R2.4 and R2.6–R2.8 fixed, R2.5 partly; no blocker. Orchestrator's list, the last round under the 3-round rule.

- [x] R3.1 Pre-existing non-DNS flows to an upstream address survive: `kill` treats the upstream table as exempt (`guard_darwin.go:89`, `:432`), but `-k` matches hosts, not ports. Stop exempting upstream addresses in `kill` (DNS re-flows through the `no state` port rule); the test at `guard_darwin_test.go:578` must catch it.
- [x] R3.2 States created during a bypass persist: `Apply` returns at `:155` before `killStates` is set, and the next success with an intact anchor skips load and kill. Set `killStates` on any Apply that follows a failed one; test it.
- [x] R3.3 Nits:
  - Each upstream gets only its own ports: per-(address, port) rules or tables, not one brace list crossing every port with every address (`pfctl_darwin.go:424`).
  - ICMPv6 135/136 to upstreams: keep them, and say in DESIGN and the checklist that they are only for an on-link upstream.
  - Checklist step 5: the HTTP-refusal test only for a global upstream (a link-local one is passed by `fe80::/10`).
  - Rollback: after kill -9 stop the process before flushing; the split routes stay until `up -connect=false`.
  - Step 2: the anchor name present, not "listed first".
  - Step 3: the counter can grow from background traffic; step 4 decides.
  - Step 0: record one real `-s states` line and run one `-k` of a throwaway IPv6 pair before trusting the parser; say how to read the results.

Resolution (round 3):
- R3.1 `exempts` (`guard_darwin.go`, the method on `appliedGuard`) is the exempt table alone. An upstream's address isn't exempt for `kill` (:403): its states go, DNS included, and DNS goes on through its stateless port rule.
  - Test: `TestApplyKillsStatesTheGuardRefuses` has an upstream state on :443 and one on :53, and requires both killed.
  - Planted bug: `exempts` sparing upstream addresses again fails it.
- R3.2 `Apply` (:139) sets `killStates` whenever the previous Apply failed. So a state a quick pass above the hook made (it keeps state by default) goes on the next success, even when the anchor is intact and isn't reloaded.
  - Test: `TestStatesMadeWhileTheGuardFailedAreKilled`: a bypass with a foreign state, Apply fails, the bypass goes, Apply succeeds without a reload, and the state is gone.
  - Planted bug: no kill after a failure fails it.
  - What is left: a bypass that comes and goes between two polls without the guard noticing leaves its states until the next successful load or failure (DESIGN says so).
- R3.3 Nits:
  - **Upstreams.** Round 2's upstream table is replaced by rules naming each global IPv6 upstream on its own port (`guardRules`, `pfctl_darwin.go:409`; `upstreamTargets` :362). Link-local upstreams are skipped: `fe80::/10` passes them whole, and pf couldn't name them without their interface. Two upstreams on different ports no longer cross.
    - Tests: `TestAnchorText`, `TestTheTableAndTheUpstreams`.
    - Planted bugs: ports crossed, and a link-local upstream named, each fail them.
  - **ICMPv6 135/136 to upstreams** are kept, per address. DESIGN, the `guardRules` comment and checklist step 2 say they are only for an on-link upstream.
  - **Checklist.** Step 5 runs the HTTP refusal only for a global upstream. The rollback says to stop thinkpol first, and that after a kill -9 the split routes stay until `up -connect=false`. Step 2 requires the anchor's name, not its place. Step 3 is suggestive and step 4 decides. Step 0 records one real `-s states` line and runs a throwaway `pfctl -k 2001:db8::1 -k 2001:db8::2`, with how to read both.
- **Only a real Mac can settle:**
  - the `-E`, References, `-s states` and `-k` outputs;
  - whether a reload narrows the table (step 8);
  - whether bound sockets reach pf (steps 3–4);
  - what a missing anchor's flush answers (step 10).

## Log
- 2026-10-15 created in backlog (split from TP-021 after 3 review rounds; the Linux guard merged in TP-021)
- 2026-10-15 backlog → in-progress — owner: claude-opus-tp078
- 2026-10-15 in-progress → review — round 1: pf guard (anchor com.apple/thinkpol, table thinkpol_exempt6, enable by reference with a boot-stamped token record, 10 s poll), agent wiring, DESIGN "IPv6". make lint, make test (with a pfctl tripwire: no test runs pfctl), go test -race (firewall, agent, routetable), lab-gotest dataplane and agent pass; nine mutations each caught. Device checklist pending (owner's run after review round 1); pfctl output formats and pf behaviour are inferences from the man pages until then
- 2026-10-15 review → has-errors — cross-family review (Grok): 1 blocker (unreadable -E token leaks the reference), 5 should-fix, nits and suspicions; findings R2.1–R2.8
- 2026-10-15 has-errors → in-progress — owner: claude-opus-tp078, round 2
- 2026-10-15 in-progress → review — round 2: R2.1–R2.8 fixed. Unreadable -E token found by pid or Apply/Close fail; ND rule dropped, MLD to ff00::/8; DNS upstreams in thinkpol_upstream6 for DNS only, upstream ports carried through Want/Exempt/Engine/agent; quick pass above the hook = not enforced; anchor com.apple/000.thinkpol; IPv6 states to non-exempt ends killed with pfctl -k; tables not const; missing anchor = empty; checklist reworked. make lint, make test (pfctl tripwire clean), -race, lab-gotest dataplane (20 pkgs) and agent (6 pkgs) pass. 17 planted bugs each caught: an unknown token held, Apply succeeding unread, Close forgetting it, MLD to any, upstreams in the exempt table, quick pass ignored, no kill, kill ignoring exemptions, kill one direction, no kill after re-enable, stateful passes accepted, Watch quiet after a failure, loose References match, const tables, missing-anchor flush failing Close, any Invalid argument taken as empty (rules, tables). Device run pending
- 2026-10-15 review → has-errors — Grok delta review of round 2: R2.5 partly fixed (upstream addresses exempt from kill, states made during a bypass), checklist nits; findings R3.1–R3.3
- 2026-10-15 has-errors → in-progress — owner: claude-opus-tp078, round 3
- 2026-10-15 in-progress → review — round 3: R3.1–R3.3 fixed. kill exempts the main table only (upstream states die, DNS re-flows statelessly); any Apply after a failed one kills states; per-(address, port) upstream DNS rules, upstream table dropped, link-local upstreams left to fe80::/10; checklist steps 0, 2, 3, 4, 5 and rollback reworked. make lint, make test (pfctl tripwire clean), -race, lab-gotest dataplane (20 pkgs) and agent (6 pkgs) pass. 4 planted bugs each caught: kill sparing upstream addresses, no kill after a failure, ports crossed, a link-local upstream named. Ready for the owner's device run; what only a real Mac settles is listed in Resolution (round 3)
- 2026-10-16 device sessions A and B recorded; native-IPv6 steps moved to TP-096
