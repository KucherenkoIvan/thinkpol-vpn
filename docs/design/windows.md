# thinkpol-vpn — Windows design

How a device meets the macOS and Linux contract on Windows (M5: TP-047, the data plane; TP-076, the kill switch). A design for review, revised after review round 1 ([appendix](#appendix-review-round-1)); nothing here is built. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md), and RR66–RR76 are rows [proposed below](#proposed-residual-risks); `[n]` are [sources](#appendix-sources).

The behaviour to match is decided: [security](security.md#kill-switch) (the kill switch, the crash posture, rollback), [routing](routing.md) (the route table, DNS), the [desktop client](desktop-client.md#the-local-api) (the local API's gates and codes), [configuration](configuration.md), TP-167's [exit codes](api-overview.md#tp-167-exit-codes-and-the-setting-shape). Where Windows can't match it, this note says so and proposes a residual row.

**Testing.** The owner proves Windows on one real device: no CI runners, no VMs (owner, 2026-11-15). Each adapter has a pure half (rule rendering, layouts, policies), unit-tested with fakes on every OS, and a thin OS half proven by device sessions ([ticket split](#ticket-split)). Device code runs as a test binary built on the development machine (`GOOS=windows go test -c -tags windowsdevice`), run elevated; it prints evidence and undoes what it changes. Nothing is built on a WFP behaviour session A0 hasn't shown.

## Seams

Windows code goes in `_windows.go` files of the package that owns each seam, where an `_other.go` stub refuses today. `cmd/thinkpol/platform.go` only wires (Windows joins `platform_guard_host.go`'s build tag). KRN-001 lets grpckit serve any `net.Listener`.

| Seam | Port | Windows provides |
|---|---|---|
| TUN | `tun.Create` (`tun_other.go:11`), `WorkerHost.NewTUN` (`agent/platform.go:31`) | Wintun via `wgtun`, `WintunTunnelType` set |
| Addresses, routes | `netcfg.Configurator` (`netcfg.go:547`), `routetable.New`, `LayoutOf` (`split.go:31`), `SocketControl` (`control_other.go:10`) | winipcfg; macOS's layout without rejects; `IP_UNICAST_IF` |
| Firewall | `routetable.Guard` (`guard.go:20`); `agent.KillSwitch` (`killswitch.go:23`), `firewall.KillSwitchRules`; `KillSwitchPlace` | one WFP engine adapter, two owners ([below](#firewall-two-owners-two-sessions)); the rules struct is unchanged |
| DNS | `dns.System`, `SetSystem`/`RestoreSystem`/`SystemUpstreams`, `Inspect` | DNS on the TUN interface; `Problem` |
| Platform | `agent.Platform`, `DeviceHost`, `ClearHost`; `supported` | device mode only |
| Host lock, connect record, crash trace | `hostlock_other.go`, `connectrecord_other.go`, `crashtrace_other.go` | `LockFileEx`; a record stamped with `BootSession`; `debug.SetCrashOutput` |
| Trusted dirs, boot session | `trusteddir.Open` (`trusteddir.go:19`), `BootSession` (`boot_linux.go:17`) | owner and DACL checks; a volatile registry key (TP-W1) |
| Service | `service.System` (`install.go:26`) behind `Runner` | `sc.exe` through the `Runner`; `Render` is canonical `sc qc`/`qfailure` text ([below](#service)) |
| Local API | `Listen` (`listen_other.go:12`), `callerOf`, `Caller`, `Policy` (`auth.go:68,85`), `Dial` | a named pipe; the OS-blind `Principal` seam ([below](#local-api-over-a-named-pipe)) |
| Diag | `agent.Inspector`; TP-133 | readers for WFP, routes, DNS, the service |

`linksMarked` (`agent/killswitch.go:104`) becomes true on Windows: the agent's app-ID permit plays the mark's part, so an entry on the LAN serving on 53 or 853 is never put in `NoDNS` and can't become a hole for other processes.

## TUN

**Decision.** Wintun through `golang.zx2c4.com/wireguard/tun` (`CreateTUNWithRequestedGUID`), a GUID derived from the name so the LUID, the interface's registry key and its firewall profile stay the same across runs (A1 confirms the LUID; the docs promise only the network entry). `tun.WintunTunnelType` defaults to `"WireGuard"` and is set to `thinkpol`. `DefaultName` is `thinkpol`.

**`wintun.dll`** is embedded only under `//go:build windows && wintun_embed`; without the tag a stub returns `ErrNoWintun`, so `make lint` and clean checkouts never need the fetched file. `make build-windows` fetches Wintun 0.14.1's zip by pinned SHA-256 and sets the tag. At start the agent compares the on-disk DLL's SHA-256 with the embedded one and rewrites it on a mismatch; the directory is admin-only [1][24].

**Leftovers.** The binding has only Create, Open, Close and Uninstall, and Close removes only an adapter this process created [2]. Wintun removes orphans when an adapter is next created [2], so a crash's adapter (if one survives, A0) goes at the restart's create; `ClearHost` reports one it finds rather than claiming to remove it.

**Lost.** WireGuard-NT (owns its UDP socket, so transports can't sit under it); tap-windows6; a driver of our own.

## Addresses and routes

**Decision.** `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg` [3] behind a `netcfg` adapter, with **macOS's layout** (`SplitRoutes`): `0/1`, `128/1` and the IPv6 `/2`s into the TUN; direct prefixes and endpoints via the default gateway; foreign routes over tunnelled space shadowed (Windows honours DHCP option 121 and RA route options).

**No reject routes.** While the TUN exists the IPv6 halves go into it even with an IPv4-only overlay, and the router refuses what the TUN can't carry; once it's gone, the [guard](#firewall-two-owners-two-sessions) refuses IPv6 and the overlay's networks off the TUN. `LayoutOf` gains a no-rejects switch.

**Ownership.** Routes on the Wintun LUID are the overlay's; uplink routes have no owner tag, so they go in a route record per owner stamped with the boot session, as on macOS (`record_darwin.go`; corrupt records follow RR53).

**Links bypass the tunnel by socket.** `SocketControl` sets `IP_UNICAST_IF` (IPv4: the index in **network byte order**) or `IPV6_UNICAST_IF` (host order) [4][30]. The links' UDP sockets are **re-bound on every default-route change**, as wireguard-windows' monitor does [4]; a socket pinned at open would keep the old uplink after Wi-Fi → Ethernet. TCP links fail over by reconnecting. Endpoint routes stay too.

**Big tables.** About 27k routes are reported very slow on Windows [5]. Diffs only (`winipcfg.SetRoutes` flushes first, so it isn't used); direct routes go in after the TUN's, tunnelled meanwhile (slow, never a leak); A1 measures 1k and 10k (question 14). Whether `CreateIpForwardEntry2` routes are active-store only is settled by A1's reboot; the record clears survivors.

**Lost.** Copying winipcfg; `route.exe`/`netsh` (slow, text, no events); a WFP "route" (needs a callout driver).

## DNS

**Decision.**
1. Windows is pointed at the node's resolver **on the TUN interface** (its servers are the resolver's overlay addresses, lowest interface metric); the DNS client's cache is flushed on connect and on each map or rule change.
2. **The guard wins.** Off the TUN, UDP and TCP 53 and 853 are refused for every process but the agent, whenever thinkpol's firewall is in place: the guard's static set while connected and after a crash, the kill switch's static set while it is on. Connected or not, allow-LAN or not. This is the mechanism of OpenVPN's `block-outside-dns` and wireguard-windows [7][8]. Smart multi-homed name resolution sends each query to every interface's servers at once, and its policy switch isn't always honoured [9], so the block is required.
3. **The OS resolver's DoH is confined.** Windows 11's DNS client can send DoH (TCP and UDP 443) to an uplink's resolver [12], past the 53/853 block. The guard refuses 443 off the TUN for the **DNS Client service (`Dnscache`) by its service SID**. WFP has no service condition as such: `FWPM_CONDITION_ALE_USER_ID` takes a security descriptor checked against the socket's token [31], a service SID is a group in its service's token, and Windows' own service-hardening rules filter services this way [32]. A0 proves it matches (`sc qsidtype dnscache` must say unrestricted; a query made while impersonating a caller would carry the caller's token instead [31]).

**The divergence** (owner question 16). With allow-LAN, Linux and macOS let DNS to the LAN out while connected (security.md). Windows doesn't: the uplink's resolver is usually the router, the guard can't tell it from any other LAN resolver, and smart multi-homed resolution would send it every query. So a LAN resolver (a Pi-hole, a local container's) is unreachable on Windows while connected (RR74). The kill switch needs no rule change: on Windows its static set refuses DNS to every destination (its `NoDNS` and `Upstreams` are covered: the agent passes by app ID), and the `LANDNS` field proposed earlier is dropped.

**Upstreams.** `SystemUpstreams` reads, through `GetAdaptersAddresses`, the DNS servers of the interfaces holding a default route, the TUN excluded. Direct queries leave from the agent, which the app-ID permit lets through.

**Lost.**
- *NRPT `.` rule* (Tailscale's split DNS [10]): any Group Policy NRPT rule makes Windows ignore local ones [10][11], it is registry state that outlives a crash, and it doesn't stop multi-homed queries.
- *Disabling multi-homed resolution*: incomplete [9] and machine-wide. *Rewriting the uplinks' DNS*: other software's state, restored after a crash.

**`RestoreDNS`** removes the TUN's DNS registry values if the adapter is gone; the setting is otherwise the adapter's. LLMNR, mDNS and NetBIOS stay the LAN's (RR7); NetBIOS over TCP/IP is off on the TUN. Apps' own DoH is RR3.

## Firewall: two owners, two sessions

The kill switch implements `agent.KillSwitch` with TP-048's shapes; the guard implements `routetable.Guard`. One WFP engine adapter serves both.

**Ownership.** Each owner has its **own provider** (`thinkpol-killswitch`, `thinkpol-guard`) and sublayer, at weight `0xFFFF` [8][15]. Our permits are soft (no `CLEAR_ACTION_RIGHT`), so a packet passes only if no sublayer blocks it [16]. Every filter has a **stable key**, derived from (owner, role, layer, slot). Every change is made by key; an owner touches only its own provider's objects; a provider or sublayer is deleted only when enumeration shows nothing of ours references it. So the kill switch's `Close` (toggle off while connected) leaves the guard whole, and a fresh guard's `Close` clearing a crashed run (`guard.go:19`) leaves the kill switch whole.

**Sessions.**

| Session | Holds | When the agent dies |
|---|---|---|
| **static**: non-dynamic, not `PERSISTENT` | providers, sublayers; the kill switch's down shape; the guard's blocks and link-scoped permits; both owners' agent and loopback permits | stays until a change by key, rollback, a BFE stop, or a full restart [17] |
| **dynamic**: `FWPM_SESSION_FLAG_DYNAMIC`, one per agent life | the TUN permits; `Direct`; the guard's direct IPv6 permits | deleted by BFE when the session ends, a crash included [17] |

The kill switch's static set is the down shape whatever the shape asked for, because on Windows nothing in the down shape depends on being connected: `Allow` is static, DNS is refused everywhere, the agent passes by app ID. A dynamic filter in a static sublayer is the permitted direction (persistent objects can't reference non-persistent ones, not the reverse [17]); A0 proves it before anything relies on it.

**Change order.** One logical change spans two sessions, so two transactions can't be one. Every change runs in this order:
1. **Add** the new dynamic permits, under the slot key not in use (dynamic transaction 1).
2. **Change the static filters by key**: delete and add the changed ones in one transaction (static). If A0 shows a key can't be re-added in the transaction that deleted it, static filters alternate slots too.
3. **Delete** the old slot's dynamic permits (dynamic transaction 2).

*Proof that no step blocks a connected member.* Within a sublayer our highest-weight match decides, so adding a permit or deleting a block only widens; across sublayers a packet passes when no sublayer blocks it, so widening one never narrows the outcome. After step 1 the state is old static + old and new dynamic: wider than the old shape. After step 2 it is new static + old and new dynamic: wider than the new shape, because the new shape's dynamic permits are already in. Step 3 narrows to exactly the new shape. A failure leaves:
- step 1: nothing changed (the transaction aborts);
- step 2: the old static set with both slots, wider than the old shape;
- step 3: wider than the new shape.

None refuses what the shape in force lets out. The failure is reported and the next tick retries; Apply enumerates the owner's provider, compares with the wanted set by key, and writes only differences, so it is idempotent. Putting an owner in place (the toggle turned on while connected) first adds its provider and an empty sublayer, which block nothing, so step 1 has a sublayer to reference. Removing an owner runs deletes in the same direction (static blocks first, then dynamic permits, then sublayer and provider). Connect and disconnect touch only the dynamic set.

**Watches.** Each owner subscribes (`FwpmFilterSubscribeChanges0`) to its own provider's filters only. A notification triggers a re-apply, which is a compare and writes only if something differs. Neither owner writes the other's objects, so the two watches can't undo each other; an owner's own writes wake only its own watch, and that compare ends the loop.

**Engine errors.** A BFE stop or crash removes every static and dynamic object, both sessions and the subscriptions [17][33]. On any engine error (RPC failure, session aborted) the adapter drops both sessions, reopens the engine with backoff while BFE is down, re-subscribes, and both owners re-apply everything. While BFE is down nothing is enforced (RR67).

**Lost.** *Dynamic only*, as wireguard-windows [8]: the kill switch would vanish on a crash. *Persistent*, as Mullvad's blocking state [15]: closes the boot window (RR66) but survives a broken install across reboots (question 10). *Boot-time filters*: only until BFE starts, and only useful with persistent filters [18].

## Service

**Decision.** A service `thinkpol`, LocalSystem, made through `sc.exe` behind the `Runner` (`sc create`, `config`, `failure`, `failureflag`, `sidtype`, `sdset`) [20][34]. `Render` produces the canonical `sc qc`, `sc qfailure` and `sc qfailureflag` text, which install compares with what `sc` reports: a hand-edited service is `ErrDefinitionChanged`, as for systemd.
- ImagePath `"%ProgramFiles%\thinkpol\thinkpol.exe" up -service`; start **automatic, not delayed** (delayed widens the boot window); dependencies `BFE`, `Nsi`, `Tcpip`; service SID unrestricted.
- **Restart:** "restart after 5 s", reset after a day, with `failureflag 1`, so an error exit restarts too. Recovery runs only when the process ends without reporting STOPPED, or reports it with a non-zero code under that flag [20].
- **Start:** the agent reports RUNNING once it holds the host lock, **before** the node starts: a slow connect is then not a start timeout (about 30 s), which SCM doesn't treat as a failure.
- **BFE stop.** `net stop bfe` stops thinkpol first (the dependency) and removes every WFP object. When asked to stop while BFE is stop-pending, the agent exits with a non-zero service code, so recovery restarts it after 5 s, and starting it starts BFE again; A0 and C prove SCM does this. If it doesn't, the tray starts a stopped service it should see running (question 15). Only administrators can stop BFE.
- **Shutdown.** Stop and preshutdown are accepted; the preshutdown timeout is left at Windows' default, 10 s since 1703 [35]. The risk is nil for safety: a stop that Windows cuts short aborts any WFP transaction in flight, which leaves the static set whole, and a full shutdown clears the static objects anyway.
- **A stop leaves the down shape** ("a stop is not a disconnect"). The tray: [desktop-client.md](desktop-client.md#the-local-api); Windows adds that the service's DACL grants the access group start, query-status and interrogate (question 15).

**Fast Startup.** Windows' default "Shut down" hibernates the kernel session rather than closing it; "Restart" doesn't use it, and `shutdown /s` does a full shutdown [21]. So a Fast Startup power-on is expected to keep the service process, BFE's static objects, the volatile boot key, the adapter and the routes: to the agent it is no boot, and connect-on-boot doesn't run. A0 proves which of these survive; only then may any wording rely on it.

**Lost.** A scheduled task (no restart or stop semantics); NSSM, WinSW (a third-party SYSTEM binary in front of ours); `svc/mgr` (API calls, no definition to compare).

## Crash posture, boot session, recovery

**After a crash** static objects stay and dynamic ones go: the kill switch's down shape (with the toggle on or under the crash posture) plus the guard's static set, as rule 7 wants (the guard outlives the agent on Linux too). So the dead agent's direct destinations go at once (RR18), DNS off the TUN is refused, IPv6 passes only link-scoped, and the overlay is refused. SCM restarts the agent in about 5 s; its start-time cleanup narrows to the down shape, clears recorded routes, then connects if the boot's record says so. Each start in the boot is counted in the connect record; five within ten minutes puts a `restart_loop` line in health (the tray shows it). Nothing more goes to disk (S2).

**Boot session.** `%ProgramData%\thinkpol\run` survives restarts, so records carry a boot session: a random nonce in the volatile key `HKLM\SOFTWARE\thinkpol\Boot`, gone at the next real boot. The key must be volatile: opening an existing non-volatile key with `REG_OPTION_VOLATILE` keeps it non-volatile [36], and the session would never change. So the agent creates it with `REG_OPTION_VOLATILE` and takes a new nonce only on `REG_CREATED_NEW_KEY`. For an existing key it checks volatility by creating a non-volatile probe subkey, which a volatile parent refuses (`ERROR_CHILD_MUST_BE_VOLATILE`) [36]; a non-volatile key is deleted and made anew, and health reports it.

**Rollback** is `thinkpol rollback` in an elevated terminal, unchanged: exit 75 while the host lock is held; it records the boot disconnected and runs `ClearHost` (recorded routes, the TUN's DNS values, both providers' objects), then reports what's left. `KillSwitchPlace` names the WFP sublayer `thinkpol-killswitch`.

**Exit codes** keep their numbers: `ERROR_ACCESS_DENIED` on a named input is 77; no pipe (`ERROR_FILE_NOT_FOUND`) is `service_down`, 69; `ERROR_PIPE_BUSY` after retries is 75.

**Crash trace.** SCM gives a service no stderr, so the agent opens `crash-trace` (SYSTEM and Administrators only) and passes it to `debug.SetCrashOutput`; `up` writes its exit error there.

### Recovery (runbook wording)

- **A full restart is the way out without thinkpol**, when the toggle is off: Start → Power → **Restart**, or `shutdown /r /t 0`. It clears the static objects, the boot session, the adapter and probably the routes. **"Shut down" is not a way out** while Fast Startup is on: it is expected to keep all of them (A0 settles it).
- **A crash loop with the toggle on** (the agent dies at each start, so the down shape is back each time):
  1. `sc config thinkpol start= disabled` (a recovery restart of a disabled service fails);
  2. `taskkill /F /IM thinkpol.exe` if one is between restarts;
  3. `thinkpol rollback`: the network is back;
  4. fix or reinstall, `sc config thinkpol start= auto`, `sc start thinkpol`, and turn the kill switch off once things work.

  A later cross-OS ticket gives rollback an option that also turns the toggle off (RR76).

## Local API over a named pipe

The gates, codes and tray behaviour are [desktop-client.md](desktop-client.md#the-local-api)'s; Windows-specific:

**Pipe.** `\\.\pipe\ProtectedPrefix\Administrators\thinkpol\api`, the `-api-socket` default. The session manager's `ProtectedPrefix\Administrators` lets only administrators and SYSTEM create pipes beneath it, so no standard user can squat the name while the service is down; Tailscale's daemon pipe lives there [23][37]. go-winio [22] serves it: it always rejects remote clients, creates the first instance exclusively, and exposes the handle (`Fd()`), so no own listener is needed.

**DACL** (protected; `O:SY`): SYSTEM and Administrators full; the access group `FILE_READ_DATA`, `FILE_WRITE_DATA`, `FILE_READ_ATTRIBUTES`, `READ_CONTROL`, `SYNCHRONIZE`, and nothing else. Never generic write: it includes `FILE_APPEND_DATA`, which on a pipe is `FILE_CREATE_PIPE_INSTANCE`, and would let a member open a server instance beside the service [38]. Clients dial with exactly those rights (go-winio's `DialPipeAccess`) at `SecurityIdentification`, since the default dial is anonymous [22][23].

**The client checks the server on every connection**: `GetSecurityInfo` on its handle must show the owner SID SYSTEM. Opening the server process's token (`OpenProcessToken`) is denied to standard users for a SYSTEM process, so it can't be the check.

**The caller, per connection.** The server impersonates at Identification level (on a locked OS thread), reads the token's user, enabled groups and elevation, and reverts: the analogue of `SO_PEERCRED`.

**Seam.** `auth.go` becomes OS-blind:
- `type Principal string`: `uid:0`, `gid:20`, or a SID string;
- `Caller{Root bool; User Principal; Groups []Principal}`, with enabled groups only (deny-only ones are dropped);
- `Policy{Service, Group Principal; HasGroup bool; Membership}`, with `Membership.IsMember(ctx, user, group Principal)`.

`callerOf_windows` maps SYSTEM, or a token with Administrators enabled, to `Root`; an unelevated admin's deny-only Administrators group is dropped, so they count as a member or no one. `Policy` and its tests run on every OS.

**Group.** A local group `thinkpol`, made by install (`net localgroup` through the `Runner`); the console session's user is added (`-user` overrides; under UAC over-the-shoulder elevation the elevated user is the admin). Membership counts from the next logon (RR43). Network Configuration Operators lost: it lets members reconfigure every adapter.

## Install and uninstall

Paths and ACLs are [configuration.md's open question](configuration.md#open-questions); signing and the package are TP-051's. Install follows today's steps (readiness, binary and DLL, group, crash-trace file, stop the old service, host lock, create or update and start).

**A foreign `%ProgramData%\thinkpol`.** Any user may create folders in `%ProgramData%`, and `trusteddir` refuses one made by someone else, with a foreign write ACE, or that is a junction. The agent keeps refusing it; install, run elevated, renames it aside (`thinkpol.untrusted-<time>`, the junction itself, never followed or read), creates a fresh one with the protected DACL, and says so: a pre-planted folder costs a re-enrolment, never a lockout.

**Uninstall** stops and deletes the service, takes the host lock and runs `ClearHost`, then removes the binary (a running one renames itself aside for deletion at restart). The group stays, as on Unix, and so does the Wintun driver.

**Architectures.** amd64 and arm64, native [27][24][28]; x64 under ARM64 emulation is unsupported. `make lint` adds `windows/arm64`.

## Mechanism (moves to package docs at their tickets)

These sections say how; each moves to its package's `doc.go` in the ticket named, and the package doc is then the source.

### Moves to `firewall/doc.go` at TP-W2b and TP-W2c

Layers: C = `ALE_AUTH_CONNECT`, R = `ALE_AUTH_RECV_ACCEPT`, F = `IPFORWARD` (ICS, the mobile hotspot, a NAT switch's forwarding if WinNAT uses it: A0), each V4 and V6 unless marked. R matters because replies to accepted inbound connections never meet C. F is per packet, so there a block drops rather than refuses. `FWP_UINT8` weights; the highest match in a sublayer decides.

| W | Kill switch | Layers | Session |
|---|---|---|---|
| 15 | permit loopback | C R | static |
| 14 | permit the agent: app ID of the installed `thinkpol.exe` **and** user LocalSystem | C R | static |
| 13 | permit the TUN (interface = its LUID) | C R F | dynamic |
| 11 | **block** DNS (UDP, TCP 53, 853) to anywhere | C | static |
| 10 | permit `Allow` (entries; the LAN with allow-LAN) | C R; F for the LAN | static |
| 9 | permit `Direct` | C R | dynamic |
| 8 | permit DHCPv4: local 68 → remote 67, and inbound from 67 to local 68; DHCPv6: 546 → 547 at `ff02::1:2`, and inbound from 547 to local 546 | C R | static |
| 7 | permit ND 135/136 to and from **anywhere**; RS 133 to `ff02::2`; RA 134 and redirect 137 from `fe80::/10`; MLD 130–132, 143 to multicast | C6 R6 | static |
| 0 | **block** all | C R F | static |

| W | Guard | Layers | Session |
|---|---|---|---|
| 15, 14 | permit loopback; permit the agent (as above) | C R | static |
| 13 | permit the TUN | C R F | dynamic |
| 12 | **block** `Dnscache` (service-SID descriptor) to remote port 443, TCP and UDP | C | static |
| 11 | **block** DNS (53, 853) | C | static |
| 10 | **block** the overlay's networks (its IPv4 range and ULA) | C R F | static |
| 9 | permit `Exempt.Direct`'s IPv6 part | C6 R6 F6 | dynamic |
| 8 | permit link-scoped: ND as above, DHCPv6 as above, `fe80::/10`, `ff02::/16` | C6 R6 | static |
| 0 | **block** IPv6 | C6 R6 F6 | static |

- `Mark`, `NoDNS` and `Upstreams` (kill switch) and `Mark` and `Upstreams` (guard) are ignored: the agent's permit covers them. The app ID is the installed path, which updates keep and only Administrators can write.
- **Address sets** are one filter with OR-ed remote-address conditions. If 10,000 conditions don't fit one filter (A0 times it), the set is chunked into filters of at most N conditions at the same weight and action; order among them doesn't matter.
- ND and MLD can't be limited by hop limit at ALE (RR70); kernel-generated ND may never meet ALE, which A0 shows.
- Interface-bound sockets (RR21) meet the same filters: ALE runs whatever routing chose.
- `diag` lists other providers' `0xFFFF` sublayers and hard permits at our layers (RR67).

### Moves to `netcfg/doc.go` at TP-W3a

Watch: `NotifyRouteChange2`, `NotifyIpInterfaceChange` and `NotifyUnicastIpAddressChange`, coalesced. Apply is all-or-nothing per owner; ownership by LUID and record; `Survey` and `Close` as the contract above `netcfg.go:547`.

### Moves to `dns/doc.go` at TP-W4

`Problem()` reports unprotected when Group Policy NRPT rules exist (their names are refused by the block: they fail, not leak; RR72), the interface write failed, the DNS block isn't enforced, or an uplink has DoH configured while the `Dnscache` confinement isn't in place (RR75). Stale and no-upstream as on the other OSes.

### Moves to the agent's diag doc at TP-W8

Readers: interface (winipcfg); routes (`GetIpForwardTable2`: ours by LUID, ours by record, foreign); WFP (`FwpmFilterEnum0` per provider, sublayer and session; whether the dynamic session is present; others' `0xFFFF` sublayers and hard permits; WFP keeps no per-filter counters); DNS (per-interface servers, local and GP NRPT, the multi-homed policy, DoH settings); the service as `sc` reports it, flagged when it differs from `Render`. `schema_version` stays 1. Offline (TP-133): the same, elevated; unelevated is 77. Evidence without thinkpol: `netsh wfp show filters`, `netsh wfp show state`, `route print`, `Get-DnsClientServerAddress`, `Get-DnsClientNrptPolicy`, `Resolve-DnsName` (not `nslookup`, which ignores NRPT [10]), `pktmon` [13].

## Proposed residual risks

Proposed, not yet in RESIDUAL-RISKS.md; numbered from the next free row after TP-217 (RR63–RR65), added when their ticket lands.

| # | Residual | When | What leaks, to whom | Breaks | Why accepted | Ticket |
|---|---|---|---|---|---|---|
| RR66 | Boot window (Windows) | toggle on, from power-on to the first apply (after a full restart; Fast Startup per A0) | what the machine sends meanwhile goes direct | D4, R2 | static objects die at restart; persistent ones would outlive a broken install (question 10) | TP-W2b |
| RR67 | WFP state not ours | a hard permit in a sublayer evaluated first; a callout driver; BFE stopped (admin only) until it's back | what it permits passes; while BFE is down, everything | D4, D6, R2 | WFP arbitration allows it; `diag` lists them; the agent re-applies when BFE is back | TP-W2a |
| RR68 | Hyper-V guests and NAT (unproven) | WSL2 (NAT, mirrored), Sandbox, Docker on Hyper-V, VMs on a NAT or external switch | unproven: possibly all their traffic direct [19] | D4, D6, R2 | RR61's counterpart; stays "unproven" until A0's WSL2 and Docker checks | TP-W2b |
| RR69 | App ID wider than a mark | kill switch or guard in place | any socket of the installed `thinkpol.exe` as LocalSystem passes | R2 | ALE matches processes; the agent opens no other outbound socket; its path is admin-only | TP-W2b |
| RR70 | ND and MLD by type | kill switch or guard in place | ND 135/136 to any address and MLD to multicast from any process | D4 | no hop limit at ALE; ND answers a solicitor's (possibly global) source (RR13's counterpart) | TP-W2b |
| RR71 | Slow direct routes | large direct sets | nothing: direct goes through the tunnel while routes install, or beyond a cap | — | narrowing direct is safe (question 14) | TP-W3b |
| RR72 | Group Policy NRPT | managed machines with NRPT rules | nothing: their names fail; health says unprotected | R4 | GP NRPT overrides local rules [11] | TP-W4 |
| RR73 | DHCP to anywhere (Windows) | kill switch in place | UDP 68 → 67 and DHCPv6 546 → 547, and their replies, from any process that binds those ports | D4, R2 | RR60's reasoning; ALE can't tell the DHCP client's svchost from another | TP-W2b |
| RR74 | No LAN resolver while connected (Windows) | connected, allow-LAN, a resolver on the LAN (a Pi-hole, a local container) | nothing: its lookups are refused; names it alone serves fail | R4 | the guard can't tell it from the router's resolver (question 16) | TP-W2c |
| RR75 | The OS resolver's DoH | an uplink with DoH set in Settings, if the `Dnscache` confinement doesn't match (shared or impersonating host) | the OS resolver's lookups to that resolver, encrypted, past the guard | R4 | confined by service SID where it matches (A0); `Problem` reports it otherwise; apps' DoH is RR3 | TP-W4 |
| RR76 | A crash loop (Windows) | the agent dies at every start | toggle on: no network but the entries; toggle off: IPv4 by address only, no names (the guard's static DNS block) | — | fails closed; the runbook's recovery (`start= disabled`, rollback); a rollback option turning the toggle off is a later cross-OS ticket | TP-W7 |

The earlier draft's squatted-pipe row is gone: only administrators can create a pipe under the protected prefix.

Existing rows: RR17's Windows half closes; RR44 drops Windows; RR18 gains "Windows: direct goes at once; names refused until restart or rollback"; RR62 gains "Windows: DNS to the LAN is refused in both shapes (RR74)"; RR58 (the kill-switch repair window, the RR58 TP-217 keeps) gains Windows' window of about a second; RR59 points to RR66; RR3, RR7, RR15, RR21–RR23, RR43 and RR51 gain Windows wording.

## Ticket split

TP-047's scope list becomes ten tickets; TP-W2b keeps TP-076's id. Plan for 1.5–2x the sizes (past estimates ran about 2x optimistic). Four device sessions:
- **A0**, at the end of W1: the throwaway probe, before any golden filter is written;
- **A1**, after W3b: routes, timings, socket binding;
- **B**, after W5: the data plane run by hand under a SYSTEM scheduled task;
- **C**, after W7: the service, and TP-076's acceptance.

**A0 proves:**
- an unsigned elevated binary runs at all (Smart App Control, if on, has no "Run anyway" [39]);
- static objects survive `taskkill /F` and dynamic ones don't;
- a dynamic filter works inside a static sublayer;
- a static replace by key while connected drops no flow (and whether existing flows are re-authorised);
- the kill switch's Close leaves the guard whole;
- a BFE restart: what's removed, whether SCM restarts the service, the adapter's reopen;
- Fast Startup: which of the service, the static objects, the volatile key, the adapter and the routes survive "Shut down";
- the pipe's access bits: a member's `CreateNamedPipe` on the name fails, a non-admin can't create under the prefix, and the owner check works;
- the DNS block under `pktmon`, and `Dnscache`'s 443 confinement with DoH set on the uplink;
- ND at ALE on native IPv6;
- the adapter's fate after a kill;
- WSL2 (NAT and mirrored), Docker and Hyper-V: `curl -4`, `curl -6`, `dig` at the uplink's resolver, with the down shape and with the guard;
- 10k-condition filters and the chunked fallback.

Pre-service sessions run the agent as a SYSTEM scheduled task (`schtasks /ru SYSTEM`) from the installed path, so the agent permit matches; the harness takes the app ID and SID to permit as parameters, so the probe can permit itself.

| Id | Title | Size | Deps | Files |
|---|---|---|---|---|
| TP-W1 | Windows build, harness, A0 probe; `BootSession`, `trusteddir` | M | — | `Makefile` (`build-windows`, `windows/arm64` lint), `tun/wintun_embed_windows.go`, `tun/wintun_stub_windows.go`, `trusteddir/trusteddir_windows.go`, `trusteddir/boot_windows.go`, `internal/windowsdevice/` (harness, probe), a runbook page |
| TP-W2a | WFP engine adapter and library spike | M | W1 | `firewall/wfp_windows.go`, `firewall/engine.go` (fake), `go.mod` |
| TP-W2b | Kill switch on WFP (TP-076) | M | W2a | `firewall/killswitch_windows.go`, `firewall/inspect_windows.go`, `firewall/testdata/`, `agent/killswitch.go` (`linksMarked`) |
| TP-W3a | Wintun and netcfg | M | W1 | `tun/tun_windows.go`, `netcfg/netcfg_windows.go`, `netcfg/watch_windows.go`, `netcfg/inspect_windows.go` |
| TP-W3b | Route table: no rejects, diffs, record, `IP_UNICAST_IF`, timings | M | W3a | `routetable/split.go`, `routetable/control_windows.go`, `netcfg/record_windows.go`, shared golden layouts |
| TP-W2c | Guard on WFP, with the DNS block and `Dnscache` confinement | M | W2a, W3b | `firewall/guard_windows.go`, `firewall/testdata/`, `cmd/thinkpol/platform_guard_host.go` |
| TP-W4 | DNS on Windows | M | W2c, W3a | `dns/system_windows.go`, `dns/inspect_windows.go`, `dns/watch_windows.go` |
| TP-W6 | Local API over a named pipe; the `Principal` seam | M | W1 | `localapi/auth.go`, `localapi/listen_windows.go`, `localapi/peercred_windows.go`, `localapi/client.go`, `localapi/group_windows.go` |
| TP-W5 | Agent platform: state, lock, record, crash trace, rollback | M | W2b, W2c, W3b, W4, W6 | `agent/hostlock_windows.go`, `agent/connectrecord_windows.go`, `agent/crashtrace_windows.go`, `agent/statedir_windows.go`, `agent/supported_windows.go`, `agent/platform.go` |
| TP-W7 | Windows service: install, uninstall, recovery, connect-on-boot | M | W5 | `service/sc_windows.go`, `service/host_windows.go`, `service/install.go`; RR66–RR76 into RESIDUAL-RISKS.md |
| TP-W8 | Windows diag (online, offline) and device checklist | S | W7, TP-133 | `agent/diagnose_windows.go`, readers in their packages |

W2a's spike checklist (library or our own thin binding): transactions; `FwpmFilterSubscribeChanges0` filtered by provider; non-dynamic and dynamic sessions side by side; add and delete by key; `ALE_USER_ID` security-descriptor conditions, a service SID among them; `IPFORWARD` layers; enumeration by provider; engine errors surfaced distinctly enough to reopen. Pin a commit.

Acceptance per ticket is the ticket's; each OS half's device checks are the session lists above, and C runs TP-076's acceptance, the crash-loop recovery and connect-on-boot across a full restart.

## Open questions for the owner

Answer as "1a 2b …".

**Your machine** (only what it is gets proven):
1. Architecture: a) x64; b) ARM64.
2. Windows: a) 11; b) 10 22H2.
3. Edition: a) Home; b) Pro or Enterprise.
4. Smart App Control: a) off; b) on or evaluation; c) don't know.
5. In use: a) none; b) WSL2 (NAT); c) WSL2 (mirrored); d) Docker Desktop or Hyper-V VMs (more than one: list them).
6. Third-party security software: a) none; b) antivirus; c) a VPN; d) both.
7. Native IPv6 at home: a) yes; b) no; c) don't know.

**Decisions:**

8. **Versions for M5.** a) Windows 11 only; b) 11, plus 10 22H2 built but labelled unsupported. *Rec: b* (both reviewers).
9. **Device sessions.** a) four (A0, A1, B, C); b) three (A1 folded into B). *Rec: a.* A0 is about an hour and settles what everything rests on.
10. **Boot window.** a) static objects, gone at a full restart (RR66); b) persistent down-shape filters while the toggle is on. *Rec: a* for M5, with A0's Fast Startup result in its wording; take b up with RR59 as one cross-OS ticket.
11. **WFP library.** a) `github.com/tailscale/wf` at a pinned commit; b) wireguard-windows' syscall layer plus the few calls it lacks; c) our own thin binding on `x/sys/windows`. *Rec: a* only if W2a's spike passes the whole checklist, else b (Fable expects b).
12. **`wintun.dll`.** a) fetched by pinned hash, embedded behind the build tag, verified and rewritten at start; b) committed; c) the user downloads it; d) shipped beside the binary by TP-051's package. *Rec: a,* d if TP-051's package makes it free.
13. **Signing for M5.** a) unsigned, with SmartScreen steps in the runbook; b) an OV certificate now; c) apply to SignPath now. *Rec: a* if question 4 is a, and c now for its lead time; details are TP-051's.
14. **If 10k direct routes are slow.** a) accept: tunnelled meanwhile; b) cap and tunnel the smallest prefixes, said in health; c) no "all but domestic" on Windows. *Rec:* decide after A1 (which times filter conditions too); default a, then b.
15. **The tray and a stopped service.** a) the group gets start, query-status and interrogate, and the tray starts a service it should see running; b) query only. *Rec: a.* Starting only restores protection, and it is the BFE-stop fallback.
16. **The LAN-DNS divergence.** a) accept: no LAN resolver while connected on Windows (RR74), stated in security.md; b) a later ticket: allow-LAN may name LAN resolvers to permit, refused when one is also an uplink's resolver; c) match the other OSes (lets lookups reach the router: rejected). *Rec: a* for M5, b if a member asks.

## Appendix: review round 1

Reviews of `394e750` (2026-11-15): go-paranoid (P), Fable 5.2 (F, in its order), pocket-torvalds (T). How each was handled.

| # | Finding | Handling |
|---|---|---|
| P1 | Shared provider: Close deletes the other owner's filters; watches ping-pong | **Changed design**: a provider per owner, stable keys, changes by key; watches per provider ([firewall](#firewall-two-owners-two-sessions)) |
| P2 | Static replace vs the dynamic session; no cross-session order | **Changed design**: add dynamic, change static by key, delete old dynamic, with the proof and what each failure leaves; A0 checks a static replace while connected |
| P3 | Pipe DACL's generic write includes `FILE_CREATE_PIPE_INSTANCE` | **Fixed**: explicit rights [38]; A0 checks a member can't create an instance |
| P4 | Squatting; `OpenProcessToken` denied to standard users | **Fixed**: the protected prefix [37]; owner-SID check per connection |
| P5 | `linksMarked` Linux-only, so LAN entries on 53/853 become a hole | **Fixed**: Windows is marked |
| P6 | Guard's DNS block vs allow-LAN; "a crash leaves exactly the down shape" | **Changed design**: the guard wins, divergence in security.md, RR74, question 16; crash wording fixed (down shape plus the guard's static set) |
| P7 | BFE stop leaves thinkpol stopped; engine handle dies | **Changed design**: reopen and re-apply on any engine error; non-zero exit on a BFE stop so recovery restarts it, tray fallback; A0, C; RR67 |
| P8 | Crash loop with the toggle on | **Fixed**: recovery steps; RR76; rollback toggle-off option as a later cross-OS ticket |
| P9 | OS DoH past the block | **Changed design**: `Dnscache` confined by service SID; `Problem`; A0; RR75 |
| P10 | IPFORWARD set, per-layer column, DHCP both ways, re-checked flows | **Fixed**: layer column, F layers, DHCP and DHCPv6 both ways; flows in A0 |
| P11 | Volatile key may be an old non-volatile one | **Fixed**: created new and volatile, checked by a probe subkey |
| P12 | `%ProgramData%\thinkpol` pre-created | **Fixed**: install renames it aside, never adopts it |
| P13 | Ticket order (W5 needs W6; session A additions) | **Fixed**: W5 depends on W6; A0 has the four checks |
| F1 | DNS blocker (W12, upstream permit never effective) | **Changed design**: as P6; W12, the upstream permit and `LANDNS` dropped |
| F2 | DoH by the OS resolver | As P9 |
| F3 | VMs and forwarding | **Fixed / device check**: F layers in both tables; WSL2 NAT and mirrored, Docker, Hyper-V in A0; RR68 "unproven" |
| F4 | Crash, Fast Startup, BFE | **Changed design**: "a restart is always a way out" dropped; recovery wording names a full restart; Fast Startup in A0; as P7 |
| F5 | Elevated `up` by hand isn't LocalSystem | **Changed design**: pre-service sessions run under a SYSTEM scheduled task; the harness takes app ID and SID |
| F6 | Pipe DACL | As P3; the server check runs per connection |
| F7 | ND limited by destination breaks | **Fixed**: 135/136 to and from anywhere; RR70 reworded |
| F8 | `IP_UNICAST_IF` pinned at open; byte order | **Fixed**: re-bound on every default-route change; IPv4 network order |
| F9 | SCM recovery, start timeout, preshutdown | **Fixed / residual risk**: RUNNING before the node; preshutdown left at 10 s, risk stated |
| F10 | Flows re-authorised; 10k conditions; LUID stability | **Device check**: A0 (flows, 10k with the chunked fallback), A1 (LUID) |
| F11 | Nits: go-winio, Wintun binding calls, tunnel type, licence tag, RR58 | **Fixed**: own-listener fallback dropped; leftovers reported, not removed; `WintunTunnelType` set; source 24 at 0.14.1; RR58 named |
| F12 | Split: probe before L tickets; split W2 | **Fixed**: A0 in W1; W2a, W2b, W2c |
| F13 | Questions | **Fixed**: machine questions 1–7; recs revised |
| T1 | Service seam assumes a definition file | **Changed design**: `sc.exe` via `Runner`, `Render` as canonical `sc` text |
| T2 | `LANDNS`/`DownNoDNS` | **Rejected**: the field is dropped (DNS refused everywhere on Windows), so there is nothing to rename or compare |
| T3 | Local API seam types | **Fixed**: `Principal`, `Caller`, `Policy`, `Membership` as proposed |
| T4 | `wintun.dll` embed breaks clean checkouts | **Fixed**: build tag, stub, hash check at start; question 12 d |
| T5 | WFP library checklist; source 29 | **Fixed**: W2a's checklist, pinned commit; source fixed |
| T6 | Split W2 and W3; `BootSession` and `trusteddir` in W1 | **Fixed** |
| T7 | Session A timing; harness identity | **Fixed**: A0 after W1, A1 after W3b; harness parameters |
| T8 | Crash loop with KS off: no names | **Residual risk**: RR76; a `restart_loop` health line, no event-log entry (S2 keeps nothing more on disk) |
| T9 | Size | **Fixed**: mechanism in marked sections; paths to configuration.md; signing to TP-051; per-section test lists deleted |
| T10 | Duplication with desktop-client.md | **Fixed**: linked; only Windows specifics kept |

## Appendix: sources

Checked 2026-11-15.

1. Wintun: <https://git.zx2c4.com/wintun/about/>
2. Wintun README (`WintunCloseAdapter` removes only what this process created; orphan cleanup): <https://git.zx2c4.com/wintun/tree/README.md>
3. `winipcfg`: <https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/luid.go>; Tailscale's use: <https://github.com/tailscale/tailscale/blob/main/wgengine/router/ifconfig_windows.go>
4. wireguard-windows default-route monitor (re-binds on change): <https://git.zx2c4.com/wireguard-windows/tree/tunnel/defaultroutemonitor.go>
5. OpenVPN forum, "Extremely long routing tables": <https://forums.openvpn.net/viewtopic.php?p=103139>
6. (dropped)
7. OpenVPN `block_dns.c`: <https://third-party-mirror.googlesource.com/openvpn/+/refs/heads/master/src/openvpn/block_dns.c>
8. wireguard-windows firewall: <https://github.com/WireGuard/wireguard-windows/tree/master/tunnel/firewall>
9. Smart multi-homed name resolution: <https://www.ovpn.com/en/blog/deactivate-smart-multi-homed-name-resolution-in-windows-8-8-1-and-10>
10. Tailscale DNS on Windows: <https://tailscale.com/docs/reference/dns-in-tailscale.md>, <https://github.com/tailscale/tailscale/blob/main/net/dns/nrpt_windows.go>
11. Microsoft, NRPT: <https://learn.microsoft.com/en-us/windows-server/networking/dns/name-resolution-policy-table>
12. Windows DoH: <https://techcommunity.microsoft.com/blog/networkingblog/windows-insiders-gain-new-dns-over-https-controls/2494644>
13. Microsoft, `pktmon`: <https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon>
14. (dropped)
15. Mullvad security doc: <https://github.com/mullvad/mullvadvpn-app/blob/main/docs/security.md>
16. Microsoft, WFP filter arbitration: <https://learn.microsoft.com/windows/win32/fwp/filter-arbitration>
17. Microsoft, WFP object management (static objects go when BFE stops or the system shuts down): <https://learn.microsoft.com/windows/win32/fwp/object-management>
18. Microsoft, WFP operation (boot-time filters): <https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation>
19. Mullvad, "Linux under WSL2 can be leaking": <https://mullvad.net/en/blog/linux-under-wsl2-can-be-leaking>
20. `SERVICE_FAILURE_ACTIONS_FLAG`: <https://learn.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-service_failure_actions_flag>
21. Fast Startup hibernates the kernel session; not used by Restart; `shutdown.exe` shuts down without it: <https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/fast-startup-causes-system-hibernation-shutdown-fail>, <https://support.microsoft.com/en-us/help/3211190>
22. go-winio: <https://pkg.go.dev/github.com/Microsoft/go-winio>
23. Tailscale `safesocket` (Identification-level dial): <https://github.com/tailscale/tailscale/blob/main/safesocket/pipe_windows.go>
24. Wintun builds and prebuilt-binaries licence: <https://www.wintun.net/>, <https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt?h=0.14.1>
25. (moved to TP-051)
26. (moved to TP-051)
27. Go 1.17 ports: <https://go.dev/doc/go1.17#ports>
28. WireGuard for Windows 0.3 (ARM64): <https://lists.zx2c4.com/pipermail/wireguard/2020-November/006075.html>
29. `wf`: <https://pkg.go.dev/github.com/tailscale/wf>; Tailscale on the Windows firewall: <https://tailscale.com/blog/windows-firewall>
30. Microsoft, `IPPROTO_IP` socket options (`IP_UNICAST_IF` in network byte order): <https://learn.microsoft.com/windows/win32/winsock/ipproto-ip-socket-options>
31. Microsoft, permitting and blocking applications and users (`ALE_USER_ID` with a security descriptor); a report of impersonated sockets carrying the user's SID: <https://learn.microsoft.com/windows/win32/fwp/permitting-and-blocking-applications-and-users>, <https://learn.microsoft.com/en-us/archive/msdn-technet-forums/f2bf0f58-6332-44ec-81c9-61e2b42097dd>
32. Microsoft, Windows Service Hardening rules and their WFP sublayer: <https://learn.microsoft.com/windows/win32/api/netfw/nn-netfw-inetfwservicerestriction>, <https://learn.microsoft.com/windows/win32/fwp/management-filtering-sublayer-identifiers>
33. Microsoft, monitoring filter changes: <https://learn.microsoft.com/windows/win32/fwp/monitoring-filter-changes>
34. Microsoft, `sc failure`, `sc failureflag`: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742011(v=ws.11)>
35. `SERVICE_PRESHUTDOWN_INFO` (10 s default since 1703): <https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_preshutdown_info>
36. `RegCreateKeyEx` (`REG_OPTION_VOLATILE` ignored for an existing key): <https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regcreatekeyexw>; `ERROR_CHILD_MUST_BE_VOLATILE` (1021): <https://learn.microsoft.com/windows/win32/debug/system-error-codes--1000-1299->
37. Protected named-pipe prefixes (SYSTEM and Administrators only under `Administrators`): <https://tyranidslair.blogspot.com/2017/>; Tailscale's pipe path: <https://github.com/tailscale/tailscale/blob/main/paths/paths.go>; hcsshim's anti-squatting use: <https://pkg.go.dev/github.com/Microsoft/hcsshim/internal/runhcs>
38. Microsoft, named pipe security and access rights (`FILE_APPEND_DATA` is `FILE_CREATE_PIPE_INSTANCE`): <https://learn.microsoft.com/windows/win32/ipc/named-pipe-security-and-access-rights>
39. Microsoft, Smart App Control: <https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003>
