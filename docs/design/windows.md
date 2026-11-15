# thinkpol-vpn — Windows design

How a device meets the macOS and Linux contract on Windows (M5: TP-047, the data plane; TP-076, the kill switch). A design for review, revised after review rounds 1 and 2; nothing here is built. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md), and RR80–RR90 are rows [proposed below](#proposed-residual-risks); `[n]` are [sources](#appendix-sources). The proposed tickets, the device sessions, A0's checklist and plan B, the owner questions ("question n") and both review rounds are in [TP-047's Notes](../../tickets/backlog/TP-047-windows-dataplane.md#notes).

The behaviour to match is decided: [security](security.md#kill-switch) (the kill switch, the crash posture, rollback), [routing](routing.md) (the route table, DNS), the [desktop client](desktop-client.md#the-local-api) (the local API's gates and codes), [configuration](configuration.md), TP-167's [exit codes](api-overview.md#tp-167-exit-codes-and-the-setting-shape). Where Windows can't match it, this note says so and proposes a residual row.

**Testing.** The owner proves Windows on one real device: no CI runners, no VMs (owner, 2026-11-15). Each adapter has a pure half (rule rendering, layouts, policies), unit-tested with fakes on every OS, and a thin OS half proven by device sessions, run as an elevated test binary built on the development machine (`GOOS=windows go test -c -tags windowsdevice`) that prints evidence and undoes its changes. Nothing is built on WFP behaviour A0 hasn't shown; where A0 says no, the plan-B table says what changes.

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
| Diag | `agent.Inspector`; TP-133 | online readers for WFP, routes, DNS, the service; offline ones are a follow-up |

`linksMarked` (`agent/killswitch.go:104`) becomes true on Windows: the agent's app-ID permit plays the mark's part, so an entry on the LAN serving on 53 or 853 is never put in `NoDNS` and can't become a hole for other processes.

## TUN

**Decision.** Wintun through `golang.zx2c4.com/wireguard/tun` (`CreateTUNWithRequestedGUID`), a GUID derived from the name so the LUID, the interface's registry key and its firewall profile stay the same across runs (A1 confirms the LUID; the docs promise only the network entry). `tun.WintunTunnelType` defaults to `"WireGuard"` and is set to `thinkpol`. `DefaultName` is `thinkpol`.

**`wintun.dll`** is embedded only under `//go:build windows && wintun_embed` (a stub returns `ErrNoWintun` otherwise, so `make lint` and clean checkouts never need it); `make build-windows` fetches Wintun 0.14.1 by pinned SHA-256 and sets the tag. At start the agent rewrites the on-disk DLL if its hash differs; the directory is admin-only [1][24].

**Leftovers.** The binding has only Create, Open, Close and Uninstall, and Close removes only an adapter this process created [2]. Wintun removes orphans when an adapter is next created [2], so a crash's adapter (if one survives, A1) goes at the restart's create; `ClearHost` reports one it finds rather than claiming to remove it.

**Lost.** WireGuard-NT (owns its UDP socket, so transports can't sit under it); tap-windows6; a driver of our own.

## Addresses and routes

**Decision.** `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg` [3] behind a `netcfg` adapter, with **macOS's layout** (`SplitRoutes`): `0/1`, `128/1` and the IPv6 `/2`s into the TUN; direct prefixes and endpoints via the default gateway; foreign routes over tunnelled space shadowed (Windows honours DHCP option 121 and RA route options).

**No reject routes.** While the TUN exists the IPv6 halves go into it even with an IPv4-only overlay, and the router refuses what the TUN can't carry; once it's gone, the [guard](#firewall-two-owners-two-sessions) refuses IPv6 and the overlay's networks off the TUN. `LayoutOf` gains a no-rejects switch.

**Ownership.** Routes on the Wintun LUID are the overlay's; uplink routes have no owner tag, so they go in a route record per owner stamped with the boot session, as on macOS (`record_darwin.go`; corrupt records follow RR53).

**Links bypass the tunnel by socket.** `SocketControl` sets `IP_UNICAST_IF` (IPv4: the index in **network byte order**) or `IPV6_UNICAST_IF` (host order) [4][30]. The links' UDP sockets are **re-bound on every default-route change**, as wireguard-windows does [4], or Wi-Fi → Ethernet would keep the old uplink; TCP links reconnect. Endpoint routes stay too.

**Big tables.** About 27k routes are reported very slow on Windows [5]. Diffs only (`winipcfg.SetRoutes` flushes first, so it isn't used); direct routes go in after the TUN's, tunnelled meanwhile (slow, never a leak); A1 measures 1k and 10k (question 14). Whether `CreateIpForwardEntry2` routes are active-store only is settled by A1's reboot; the record clears survivors.

**Lost.** Copying winipcfg; `route.exe`/`netsh` (slow, text, no events); a WFP "route" (needs a callout driver).

## DNS

**Decision.**
1. Windows is pointed at the node's resolver **on the TUN interface** (its servers are the resolver's overlay addresses, lowest interface metric); the DNS client's cache is flushed on connect and on each map or rule change.
2. **The guard wins.** Off the TUN, UDP and TCP 53 and 853 are refused for every process but the agent whenever thinkpol's firewall is in place (the guard's static set while connected and after a crash, the kill switch's while it is on), allow-LAN or not, as OpenVPN's `block-outside-dns` and wireguard-windows do [7][8]. Smart multi-homed name resolution sends each query to every interface's servers, and its policy switch isn't always honoured [9], so the block is required.
3. **The OS resolver is confined to the TUN.** Windows 11's DNS client can send DoH to an uplink's resolver [12], past the 53/853 block, and a DoH template may name any port. So both owners refuse the **DNS Client service (`Dnscache`)** every remote port off the TUN but 5353 and 5355 (mDNS and LLMNR, which stay the LAN's: RR7), matched **by its service SID**: `FWPM_CONDITION_ALE_USER_ID` takes a security descriptor checked against the socket's token [31], a service SID is a group in its service's token, and Windows' service-hardening rules filter services this way [32]. A query made while impersonating carries the caller's token instead [31] (RR89).
4. **Only while `Dnscache` runs alone.** Below about 3.5 GB of memory Windows shares svchost processes between services [40], and a service SID then matches the whole process: the block could cut the DHCP client. So each apply checks that no other service shares `Dnscache`'s process ID (`EnumServicesStatusEx`); if one does, the block isn't placed and `Problem` says so (RR89). A0 checks `tasklist /svc` and the token.

**The divergence** (question 16). With allow-LAN, Linux and macOS let DNS to the LAN out while connected (security.md). Windows doesn't: the uplink's resolver is usually the router, the guard can't tell it from another LAN resolver, and smart multi-homed resolution would send it every query. Also Windows-only: a resolver among the direct destinations (a domestic one, one an app hard-codes) is refused, as the DNS block outranks `Direct` (RR88); and a stop or crash with the toggle off leaves the guard's static set, so no names resolve until the agent runs again or rollback (RR90). The kill switch's rules don't change: its static set refuses DNS everywhere (`NoDNS` and `Upstreams` are covered by the agent's app-ID permit).

**Upstreams.** `SystemUpstreams` reads, through `GetAdaptersAddresses`, the DNS servers of the interfaces holding a default route, the TUN excluded. Direct queries leave from the agent, which the app-ID permit lets through.

**Lost.**
- *NRPT `.` rule* (Tailscale's split DNS [10]): any Group Policy NRPT rule makes Windows ignore local ones [10][11], it is registry state that outlives a crash, and it doesn't stop multi-homed queries.
- *Disabling multi-homed resolution*: incomplete [9] and machine-wide. *Rewriting the uplinks' DNS*: other software's state, restored after a crash.

**`RestoreDNS`** removes the TUN's DNS registry values if the adapter is gone; the setting is otherwise the adapter's. LLMNR, mDNS and NetBIOS stay the LAN's (RR7); NetBIOS over TCP/IP is off on the TUN. Apps' own DoH is RR3.

## Firewall: two owners, two sessions

The kill switch implements `agent.KillSwitch` with TP-048's shapes; the guard implements `routetable.Guard`. One WFP engine adapter serves both.

**Ownership.** Each owner has its **own provider** (`thinkpol-killswitch`, `thinkpol-guard`) and sublayer, at weight `0xFFFF` [8][15]. Our permits are soft (no `CLEAR_ACTION_RIGHT`), so a packet passes only if no sublayer blocks it [16]. Every filter has a **stable key**, derived from (owner, role, layer, slot). Every change is made by key, an owner touches only its own provider's objects, and a provider or sublayer goes only when nothing of ours references it. So either owner's `Close` (the toggle off while connected; a fresh guard clearing a crashed run, `guard.go:19`) leaves the other whole.

**Sessions.**

| Session | Holds | When the agent dies |
|---|---|---|
| **static**: non-dynamic, not `PERSISTENT` | providers, sublayers; the kill switch's down shape; the guard's blocks and link-scoped permits; both owners' agent and loopback permits | stays until a change by key, rollback, a BFE stop, or a full restart [17] |
| **dynamic**: `FWPM_SESSION_FLAG_DYNAMIC`, opened at connect, closed going down | the TUN permits; `Direct`; the guard's direct IPv6 permits | deleted by BFE when the session ends, a crash included [17] |

The kill switch's static set is the down shape whatever the shape asked for, because on Windows nothing in the down shape depends on being connected: `Allow` is static, DNS is refused everywhere, the agent passes by app ID. A dynamic filter in a static sublayer is the permitted direction (persistent objects can't reference non-persistent ones, not the reverse [17]); A0 proves it before anything relies on it.

**One lock.** A WFP transaction belongs to its session handle, and both owners share the two handles, so one adapter lock serializes every transaction on either session, every re-apply (tick, watch, reopen) and the reopen itself; a change's three steps run under it as one. A0 shows what two transactions on one session do; the lock stays either way.

**Change order while up.** One logical change spans two sessions, so two transactions can't be one:
1. **Add** the new dynamic permits, under the slot key not in use (dynamic transaction 1).
2. **Change the static filters by key**: delete and add the changed ones in one transaction (static). If A0 shows a key can't be re-added in the transaction that deleted it, static filters alternate slots too.
3. **Delete** the old slot's dynamic permits (dynamic transaction 2).

Within a sublayer our highest-weight match decides; across sublayers a packet passes when no sublayer blocks it. The states are old static + both slots, then new static + both slots, then the new shape; a failed step leaves the state before it (a transaction aborts whole).
- **Leaks:** none: every state lets out at most what the old or the new shape does (a block added in step 2 outranks an old permit).
- **Blocks:** none: every state lets out what the shape in force allows (the old until step 2 commits, the new after), since the new permits are in first.

A failure is reported and the next tick retries; Apply compares the owner's provider with the wanted set by key and writes only differences. Putting an owner in place first adds its provider and an empty sublayer, so step 1 has one to reference.

**Going down** (a tunnel drop or a disconnect) **closes the dynamic session** (`FwpmEngineClose0`): BFE deletes all of it as the session ends [17], both owners' TUN permits, `Direct` and the guard's direct IPv6 permits at once, where deletes by key could half-fail and leave the old `Direct` open to every process. Then the static sets change by key: on a disconnect the guard goes, and the kill switch too unless the toggle or the crash posture holds it. The next connect opens a new dynamic session.
- **Leaks:** only between the drop and the close, as on every OS. A close that errs still drops the handle; if enumeration then finds a dynamic filter of ours, the agent exits non-zero and BFE ends the session as after a crash, under a second later. A0 proves both deletions.
- **Blocks:** between the close and the static change, the down shape plus the guard's static set (global IPv6 and the overlay refused), also after a failed static change until the next tick; under the "space" preset with the toggle off, a tunnel drop keeps the guard without its direct IPv6 permits until the reconnect.

Removing an owner while up deletes its static set in one transaction, then its dynamic permits by key, then its sublayer and provider: each state is wider than the last, and the target has no such owner.

**Watches.** Each owner subscribes (`FwpmFilterSubscribeChanges0`) to its own provider's filters only; a notification triggers a re-apply under the lock, a compare that writes only differences. Neither owner writes the other's objects, so the watches can't undo each other, and an owner's own writes end in a compare that finds nothing.

**Engine errors** are exactly a dead handle (`ERROR_INVALID_HANDLE`), `RPC_S_SERVER_UNAVAILABLE` and `FWP_E_SESSION_ABORTED`: what a BFE stop or crash produces, having removed every object, both sessions and the subscriptions [17][33]. On one the adapter drops both sessions, reopens with backoff, re-subscribes, and at once re-applies each owner's last wanted set itself, not waiting for the keeper, whose skip (`killswitch.go:236`) would leave nothing enforced for up to 5 s. Any other error (`FWP_E_TIMEOUT` behind another product's long transaction, a conflict) fails that change alone and the sessions stay, so a slow neighbour never drops a connected member's TUN permits. While BFE is down nothing is enforced (RR81).

**Lost.** *Dynamic only*, as wireguard-windows [8]: the kill switch would vanish on a crash. *Persistent*, as Mullvad's blocking state [15]: closes the boot window (RR80) but survives a broken install across reboots (question 10). *Boot-time filters*: only until BFE starts, and only useful with persistent filters [18].

## Service

**Decision.** A service `thinkpol`, LocalSystem, made through `sc.exe` behind the `Runner` (`sc create`, `config`, `failure`, `failureflag`, `sidtype`, `sdset`) [20][34]. `Render` produces the canonical `sc qc`, `sc qfailure` and `sc qfailureflag` text, which install compares with what `sc.exe` reports: a hand-edited service is `ErrDefinitionChanged`, as for systemd.
- ImagePath `"%ProgramFiles%\thinkpol\thinkpol.exe" up -service`; start **automatic, not delayed** (delayed widens the boot window); dependencies `BFE`, `Nsi`, `Tcpip`; service SID unrestricted.
- **Restart:** "restart after 5 s", reset after a day, with `failureflag 1`, so an error exit restarts too. Recovery runs only when the process ends without reporting STOPPED, or reports it with a non-zero code under that flag [20].
- **Start:** the agent reports RUNNING once it holds the host lock, **before** the node starts: a slow connect is then not a start timeout (about 30 s), which SCM doesn't treat as a failure. Its first engine open backs off until BFE answers: BFE reports RUNNING before its RPC interface does, and a start that failed on it would count toward `restart_loop`.
- **Stops restart.** Every stop but a shutdown exits with a non-zero service code unless install, uninstall or update marked it intended (a marker in `run\`, stamped with the boot session), so any `sc.exe stop`, `net stop` or `Stop-Service` is followed by a restart 5 s later; to keep it stopped, disable it first ([recovery](#recovery-runbook-wording)). The reason is BFE: it won't stop while dependents run, so `net stop bfe` stops thinkpol first while BFE is still RUNNING, and the agent can't tell that stop from another. The restart starts BFE again (a dependency). A0 proves the order with a throwaway service, C the restart; failing that, the tray starts the service (question 15).
- **Shutdown.** Stop and preshutdown are accepted, at Windows' default 10 s preshutdown timeout [35]; a stop cut short aborts any WFP transaction in flight, leaving the static set whole.
- **A stop leaves the down shape** ("a stop is not a disconnect"). The tray: [desktop-client.md](desktop-client.md#the-local-api); Windows adds that the service's DACL grants the access group start, query-status and interrogate (question 15).

**Fast Startup.** Windows' default "Shut down" hibernates the kernel session; "Restart" and `shutdown /s` don't [21]. A Fast Startup power-on is expected to keep the service process, BFE's static objects, the volatile boot key, the adapter and the routes: to the agent it is no boot, and connect-on-boot doesn't run. A0 proves which survive before any wording relies on it.

**Lost.** A scheduled task (no restart or stop semantics); NSSM, WinSW (a third-party SYSTEM binary in front of ours); `svc/mgr` (API calls, no definition to compare).

## Crash posture, boot session, recovery

**After a crash** static objects stay and dynamic ones go: the kill switch's down shape (toggle on or crash posture) plus the guard's static set, as rule 7 wants. So direct destinations go at once (RR18), DNS off the TUN, IPv6 beyond link scope and the overlay are refused. SCM restarts the agent in about 5 s; its start-time cleanup narrows to the down shape, clears recorded routes, then connects if the boot's record says so.

**Restart loops.** Each start in the boot is counted in the connect record; five within ten minutes puts `restart_loop` in health. An agent dying in its first second never serves it, so while the pipe is absent the tray reads SCM's status (query-status) and calls three process-ID changes within ten minutes a restart loop, showing the one-step recovery. Nothing more goes to disk (S2).

**Boot session.** `%ProgramData%\thinkpol\run` survives restarts, so records carry a boot session: a random nonce in the volatile key `HKLM\SOFTWARE\thinkpol\Boot`, gone at the next real boot. `REG_OPTION_VOLATILE` doesn't change an existing key [36], so the agent takes a new nonce only on `REG_CREATED_NEW_KEY`, and checks an existing key with a non-volatile probe subkey, which a volatile parent refuses (`ERROR_CHILD_MUST_BE_VOLATILE`) [36]; a non-volatile key is deleted and made anew, and health reports it.

**Rollback** is `thinkpol rollback` in an elevated terminal: exit 75 while the host lock is held; it records the boot disconnected and runs `ClearHost` (recorded routes, the TUN's DNS values, both providers' objects), then reports what's left. `KillSwitchPlace` names the WFP sublayer `thinkpol-killswitch`. Two cross-OS additions (TP-W5): `-kill-switch-off` also writes the toggle off in the device file, so the next start comes up disconnected with nothing in place; and `-wait` retries the host lock for up to 15 s, which a start that dies at once holds for under a second.

**Exit codes** keep their numbers: `ERROR_ACCESS_DENIED` on a named input is 77; no pipe (`ERROR_FILE_NOT_FOUND`) is `service_down`, 69; `ERROR_PIPE_BUSY` after retries is 75.

**Crash trace.** SCM gives a service no stderr, so the agent opens `crash-trace` (SYSTEM and Administrators only) and passes it to `debug.SetCrashOutput`; `up` writes its exit error there.

**The stop note** (`KillSwitchStopNote`, `killswitch.go:78`) gets Windows wording in TP-W5: "a stop leaves the kill switch in place, as a crash does, and the service restarts in 5 s: only the entries (and the LAN with allow-LAN, its DNS refused) are reachable, and no names resolve, until the agent runs again; to stop with traffic going direct, run `thinkpol kill-switch off` and `thinkpol disconnect` first; to get the network back without it, use Start → thinkpol: restore network".

### Recovery (runbook wording)

- **One step, for any member** (the agent dies at each start, toggle on or off): Start → **thinkpol: restore network**, then accept the administrator prompt. Install (TP-W7) makes the shortcut; it runs `thinkpol.exe rollback -kill-switch-off -wait` elevated. The network is back, the service keeps restarting harmlessly and the tray shows the loop, until someone fixes or reinstalls it and turns the kill switch on again.
- **By hand**, in an elevated Command Prompt (always `sc.exe`: in PowerShell `sc` is `Set-Content`). Disable restarts, kill the agent if one is running (between restarts there is none), clear what's left:
  ```bat
  sc.exe config thinkpol start= disabled
  taskkill /F /IM thinkpol.exe
  "%ProgramFiles%\thinkpol\thinkpol.exe" rollback -kill-switch-off
  ```
  After fixing or reinstalling: `sc.exe config thinkpol start= auto`, `sc.exe start thinkpol`, then the kill switch on.
- **A full restart is the way out without thinkpol**, when the toggle is off: Start → Power → **Restart**, or `shutdown /r /t 0`. It clears the static objects, the boot session, the adapter and probably the routes. **"Shut down" is not a way out** while Fast Startup is on: it is expected to keep all of them (A0 settles it).

## Local API over a named pipe

The gates, codes and tray behaviour are [desktop-client.md](desktop-client.md#the-local-api)'s; Windows-specific:

**Pipe.** `\\.\pipe\ProtectedPrefix\Administrators\thinkpol\api`, the `-api-socket` default. The session manager's `ProtectedPrefix\Administrators` lets only administrators and SYSTEM create pipes beneath it, so no standard user can squat the name while the service is down; Tailscale's daemon pipe lives there [23][37]. go-winio [22] serves it: it always rejects remote clients, creates the first instance exclusively, and exposes the handle (`Fd()`), so no own listener is needed.

**A failed Listen isn't fatal** (a name taken in the restart gap, under the prefix only by an administrator): the data plane keeps running, Listen retries with backoff, and health reports `local_api_unavailable` (log and diag; the tray sees `service_down`). A fatal Listen would make a squatted name a restart loop.

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

Paths and ACLs are [configuration.md's open question](configuration.md#open-questions); signing and the package are TP-051's. Install follows today's steps (readiness, binary and DLL, group, crash-trace file, stop the old service with the intended-stop marker, host lock, create or update and start) and adds the Start-menu shortcut "thinkpol: restore network" (run as administrator).

**A foreign `%ProgramData%\thinkpol`.** Any user may create folders in `%ProgramData%`; `trusteddir` refuses one made by someone else, with a foreign write ACE, or a junction. Install renames it aside (`thinkpol.untrusted-<time>`, never following a junction), creates a fresh one with the protected DACL, and says so: a pre-planted folder costs a re-enrolment, never a lockout.

**Uninstall** marks the stop intended, stops and deletes the service, takes the host lock and runs `ClearHost`, then removes the binary and the shortcut (a running binary renames itself aside for deletion at restart). The group stays, as on Unix, and so does the Wintun driver.

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
| 12 | **block** `Dnscache` (service-SID descriptor), every remote port but 5353 and 5355; only while it runs alone | C | static |
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
| 12 | **block** `Dnscache` (as above) | C | static |
| 11 | **block** DNS (53, 853) | C | static |
| 10 | **block** the overlay's networks (its IPv4 range and ULA) | C R F | static |
| 9 | permit `Exempt.Direct`'s IPv6 part | C6 R6 F6 | dynamic |
| 8 | permit link-scoped: ND as above, DHCPv6 as above, `fe80::/10`, `ff02::/16` | C6 R6 | static |
| 0 | **block** IPv6 | C6 R6 F6 | static |

- `Mark`, `NoDNS` and `Upstreams` (kill switch) and `Mark` and `Upstreams` (guard) are ignored: the agent's permit covers them. The app ID is the installed path, which updates keep and only Administrators can write.
- **Address sets** are one filter with OR-ed remote-address conditions. If 10,000 conditions don't fit one filter (A0 times it), the set is chunked into filters of at most N conditions at the same weight and action; order among them doesn't matter.
- ND and MLD can't be limited by hop limit at ALE (RR84); kernel-generated ND may never meet ALE, which A0 shows on native IPv6.
- Interface-bound sockets (RR21) meet the same filters: ALE runs whatever routing chose.
- `diag` lists other providers' `0xFFFF` sublayers and hard permits at our layers (RR81).

### Moves to `netcfg/doc.go` at TP-W3a

Watch: `NotifyRouteChange2`, `NotifyIpInterfaceChange` and `NotifyUnicastIpAddressChange`, coalesced. Apply is all-or-nothing per owner; ownership by LUID and record; `Survey` and `Close` as the contract above `netcfg.go:547`.

### Moves to `dns/doc.go` at TP-W4

`Problem()` reports unprotected when Group Policy NRPT rules exist (their names are refused by the block: they fail, not leak; RR86), the interface write failed, the DNS block isn't enforced, or an uplink has DoH configured while the `Dnscache` block isn't in place (shared process, RR89). Stale and no-upstream as on the other OSes.

### Moves to the agent's diag doc at TP-W8

Readers: interface (winipcfg); routes (`GetIpForwardTable2`: ours by LUID, ours by record, foreign); WFP (`FwpmFilterEnum0` per provider, sublayer and session; whether the dynamic session is present; others' `0xFFFF` sublayers and hard permits; WFP keeps no per-filter counters); DNS (per-interface servers, local and GP NRPT, the multi-homed policy, DoH settings, whether `Dnscache` runs alone); the service as `sc.exe` reports it, flagged when it differs from `Render`. `schema_version` stays 1. Offline readers (TP-133's, on Windows: elevated, unelevated is 77) are a proposed follow-up. Evidence without thinkpol: `netsh wfp show filters`, `netsh wfp show state`, `route print`, `Get-DnsClientServerAddress`, `Get-DnsClientNrptPolicy`, `Resolve-DnsName` (not `nslookup`, which ignores NRPT [10]), `pktmon` [13].

## Proposed residual risks

Proposed, not yet in RESIDUAL-RISKS.md. Numbered from RR80 to stay clear of the rows M3's design proposes from RR66; the final numbers are set when the tickets are filed.

| # | Residual | When | What leaks, to whom | Breaks | Why accepted | Ticket |
|---|---|---|---|---|---|---|
| RR80 | Boot window (Windows) | toggle on, from power-on to the first apply (after a full restart; Fast Startup per A0) | what the machine sends meanwhile goes direct | D4, R2 | static objects die at restart; persistent ones would outlive a broken install (question 10) | TP-W2b |
| RR81 | WFP state not ours | a hard permit in a sublayer evaluated first; a callout driver; BFE stopped (admin only) until it's back | what it permits passes; while BFE is down, everything | D4, D6, R2 | WFP arbitration allows it; `diag` lists them; the agent re-applies when BFE is back, and a stop restarts it | TP-W2a |
| RR82 | Hyper-V guests and NAT (unproven) | WSL2 (NAT, mirrored), Sandbox, Docker on Hyper-V, VMs on a NAT or external switch | unproven: possibly all their traffic direct [19] | D4, D6, R2 | RR61's counterpart; stays "unproven" until a device with them runs A0's checks | TP-W2b |
| RR83 | App ID wider than a mark | kill switch or guard in place | any socket of the installed `thinkpol.exe` as LocalSystem passes | R2 | ALE matches processes; the agent opens no other outbound socket; its path is admin-only | TP-W2b |
| RR84 | ND and MLD by type | kill switch or guard in place | ND 135/136 to any address and MLD to multicast from any process | D4 | no hop limit at ALE; ND answers a solicitor's (possibly global) source (RR13's counterpart); unproven without native IPv6 | TP-W2b |
| RR85 | Slow direct routes | large direct sets | nothing: direct goes through the tunnel while routes install, or beyond a cap | — | narrowing direct is safe (question 14) | TP-W3b |
| RR86 | Group Policy NRPT | managed machines with NRPT rules | nothing: their names fail; health says unprotected | R4 | GP NRPT overrides local rules [11] | TP-W4 |
| RR87 | DHCP to anywhere (Windows) | kill switch in place | UDP 68 → 67 and DHCPv6 546 → 547, and their replies, from any process that binds those ports | D4, R2 | RR60's reasoning; ALE can't tell the DHCP client's svchost from another | TP-W2b |
| RR88 | No LAN or direct-set resolver (Windows) | connected (and in the down shape), a resolver on the LAN with allow-LAN (a Pi-hole, a local container) or among the direct destinations (a domestic one, one an app hard-codes) | nothing: lookups to it are refused; names it alone serves fail, and apps that hard-code it fail on Windows only | R4 | the DNS block outranks `Allow` and `Direct`; the guard can't tell a LAN resolver from the router's (question 16) | TP-W2c |
| RR89 | The OS resolver's DoH | an uplink with DoH set in Settings, while `Dnscache` shares its svchost (low-memory machines) or queries while impersonating | the OS resolver's lookups to that resolver, encrypted, past the guard | R4 | confined by service SID where it runs alone (A0); `Problem` reports it otherwise; apps' DoH is RR3 | TP-W4 |
| RR90 | A restart loop (Windows) | the agent dies at every start | toggle on: no network but the entries; toggle off: IPv4 by address only, no names (the guard's static DNS block) | — | fails closed; one step out (restore network: rollback `-kill-switch-off`); the tray infers the loop from SCM | TP-W5, TP-W7 |

The earlier draft's squatted-pipe row is gone: only administrators can create a pipe under the protected prefix, and a failed Listen isn't fatal.

Existing rows: RR17's Windows half closes; RR44 drops Windows; RR18 gains "Windows: direct goes at once; names refused until restart or rollback"; RR62 gains "Windows: DNS to the LAN, and `Dnscache` on any port, is refused in both shapes (RR88)"; RR58 (the kill-switch repair window, the RR58 TP-217 keeps) gains Windows' window of about a second; RR59 points to RR80; RR3, RR7, RR15, RR21–RR23, RR43 and RR51 gain Windows wording.

## Appendix: sources

Checked 2026-11-15.

1. Wintun: <https://git.zx2c4.com/wintun/about/>
2. Wintun README: <https://git.zx2c4.com/wintun/tree/README.md>
3. `winipcfg`: <https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/luid.go>; Tailscale's use: <https://github.com/tailscale/tailscale/blob/main/wgengine/router/ifconfig_windows.go>
4. wireguard-windows default-route monitor: <https://git.zx2c4.com/wireguard-windows/tree/tunnel/defaultroutemonitor.go>
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
17. Microsoft, WFP object management: <https://learn.microsoft.com/windows/win32/fwp/object-management>
18. Microsoft, WFP operation: <https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation>
19. Mullvad, "Linux under WSL2 can be leaking": <https://mullvad.net/en/blog/linux-under-wsl2-can-be-leaking>
20. `SERVICE_FAILURE_ACTIONS_FLAG`: <https://learn.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-service_failure_actions_flag>
21. Fast Startup: <https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/fast-startup-causes-system-hibernation-shutdown-fail>, <https://support.microsoft.com/en-us/help/3211190>
22. go-winio: <https://pkg.go.dev/github.com/Microsoft/go-winio>
23. Tailscale `safesocket`: <https://github.com/tailscale/tailscale/blob/main/safesocket/pipe_windows.go>
24. Wintun builds and prebuilt-binaries licence: <https://www.wintun.net/>, <https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt?h=0.14.1>
25. (moved to TP-051)
26. (moved to TP-051)
27. Go 1.17 ports: <https://go.dev/doc/go1.17#ports>
28. WireGuard for Windows 0.3 (ARM64): <https://lists.zx2c4.com/pipermail/wireguard/2020-November/006075.html>
29. `wf`: <https://pkg.go.dev/github.com/tailscale/wf>; Tailscale on the Windows firewall: <https://tailscale.com/blog/windows-firewall>
30. Microsoft, `IPPROTO_IP` socket options: <https://learn.microsoft.com/windows/win32/winsock/ipproto-ip-socket-options>
31. Microsoft, permitting and blocking applications and users; impersonated sockets carry the user's SID: <https://learn.microsoft.com/windows/win32/fwp/permitting-and-blocking-applications-and-users>, <https://learn.microsoft.com/en-us/archive/msdn-technet-forums/f2bf0f58-6332-44ec-81c9-61e2b42097dd>
32. Microsoft, Windows Service Hardening rules and their WFP sublayer: <https://learn.microsoft.com/windows/win32/api/netfw/nn-netfw-inetfwservicerestriction>, <https://learn.microsoft.com/windows/win32/fwp/management-filtering-sublayer-identifiers>
33. Microsoft, monitoring filter changes: <https://learn.microsoft.com/windows/win32/fwp/monitoring-filter-changes>
34. Microsoft, `sc failure`, `sc failureflag`: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742011(v=ws.11)>
35. `SERVICE_PRESHUTDOWN_INFO`: <https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_preshutdown_info>
36. `RegCreateKeyEx`: <https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regcreatekeyexw>; `ERROR_CHILD_MUST_BE_VOLATILE` (1021): <https://learn.microsoft.com/windows/win32/debug/system-error-codes--1000-1299->
37. Protected named-pipe prefixes: <https://tyranidslair.blogspot.com/2017/>; Tailscale's pipe path: <https://github.com/tailscale/tailscale/blob/main/paths/paths.go>; hcsshim's anti-squatting use: <https://pkg.go.dev/github.com/Microsoft/hcsshim/internal/runhcs>
38. Microsoft, named pipe security and access rights: <https://learn.microsoft.com/windows/win32/ipc/named-pipe-security-and-access-rights>
39. Microsoft, Smart App Control: <https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003>
40. Microsoft, service host grouping: <https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring>
