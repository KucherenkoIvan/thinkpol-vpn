# thinkpol-vpn — Windows design

How a device meets the macOS and Linux contract on Windows (M5: TP-047, the data plane; TP-076, the kill switch). A design for review after four rounds; nothing here is built. Entry point: [DESIGN.md](../../DESIGN.md); `RRn` are [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md) rows, RR80–RR91 [proposed below](#proposed-residual-risks); `[n]` are [sources](#appendix-sources). The ticket split, device sessions, A0's checklist, plan B, owner questions ("question n") and review rounds are in [TP-047's Notes](../../tickets/backlog/TP-047-windows-dataplane.md#notes).

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

`linksMarked` (`agent/killswitch.go:104`) becomes true on Windows: an entry on the LAN serving on 53 or 853 stays in `NoDNS`, and the agent's app-ID permit, like the mark, lets the agent through.

## TUN

**Decision.** Wintun through `golang.zx2c4.com/wireguard/tun` (`CreateTUNWithRequestedGUID`), a GUID derived from the name so the LUID, the interface's registry key and its firewall profile stay the same across runs (A1 confirms the LUID; the docs promise only the network entry). `tun.WintunTunnelType` defaults to `"WireGuard"` and is set to `thinkpol`. `DefaultName` is `thinkpol`.

**`wintun.dll`** is embedded only under `//go:build windows && wintun_embed` (a stub returns `ErrNoWintun` otherwise, so `make lint` and clean checkouts never need it); `make build-windows` fetches Wintun 0.14.1 by pinned SHA-256 and sets the tag. At start the agent rewrites the on-disk DLL if its hash differs; the directory is admin-only [1][24].

**Leftovers.** The binding has only Create, Open, Close and Uninstall, and Close removes only an adapter this process created [2]. A crash's adapter, if one survives, is **reused** by the restart's create (`tun/tun_windows.go:66-67` in the pinned wireguard-go), so netcfg flushes its addresses, routes and DNS values itself; until A1 records its fate, nothing claims it is gone. `ClearHost` reports one it finds.

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
3. **The OS resolver is confined to the TUN.** Windows 11's DNS client can send DoH to an uplink's resolver [12], past the 53/853 block, and a DoH template may name any port. So both owners refuse the **DNS Client service (`Dnscache`)** every unicast and broadcast destination off the TUN, any port (destination address type [43]); only multicast, where mDNS and LLMNR go, stays the LAN's (RR7), so a DoH template on 5353 or 5355 is refused too. It is matched **by its service SID**: `FWPM_CONDITION_ALE_USER_ID` takes a security descriptor checked against the socket's token [31], a service SID is a group in its service's token, and Windows' service-hardening rules filter services this way [32]. A query made while impersonating carries the caller's token instead [31] (RR89).
4. **Only while `Dnscache` runs alone.** Below about 3.5 GB of memory Windows shares svchost processes between services [40], and a service SID then matches the whole process: the block could cut the DHCP client. So each apply checks that no other service shares `Dnscache`'s process ID (`EnumServicesStatusEx`); if one does, the block isn't placed and `Problem` says so (RR89). A0 checks `tasklist /svc` and the token.

**The divergence** (question 16; [security.md](security.md#kill-switch) states it). With allow-LAN, Linux and macOS let DNS to the LAN out while connected; Windows can't tell the router's resolver from another LAN one, and multi-homed resolution would send it every query. So on Windows only, LAN and direct-set resolvers are refused (RR88), and a stop or crash with the toggle off leaves no names (RR90). The kill switch's static set refuses DNS everywhere (`NoDNS` and `Upstreams` covered by the agent's permit).

**Upstreams.** `SystemUpstreams` reads, through `GetAdaptersAddresses`, the DNS servers of the interfaces holding a default route, the TUN excluded. Direct queries leave from the agent, which the app-ID permit lets through.

**Lost.**
- *NRPT `.` rule* (Tailscale's [10]): any Group Policy NRPT rule makes Windows ignore local ones [10][11]; registry state outliving a crash; multi-homed queries go on.
- *Disabling multi-homed resolution*: incomplete [9], machine-wide. *Rewriting the uplinks' DNS*: others' state, restored after a crash.

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

The states are old static + both slots, then new static + both slots, then the new shape. A failed step doesn't undo the ones before it (the process and its dynamic session live on).
- **Leaks:** the union of the old and new `Direct`, wider than either, while both slots are in: between steps 1 and 3, and after a failed step 2 or 3 until the next apply (within 10 s) deletes the unwanted slot; health shows the extra slot meanwhile. A crash drops both with the session.
- **Blocks:** none: every state lets out what the shape in force allows (the old until step 2 commits, the new after), since the new permits are in first.

A failure is reported and the next tick retries; Apply compares the owner's provider with the wanted set by key and writes only differences. Putting an owner in place first adds its provider and an empty sublayer, so step 1 has one to reference.

**Going down** (a tunnel drop or a disconnect) **closes the dynamic session** (`FwpmEngineClose0`): BFE deletes all of it at once [17] (TUN permits, `Direct`, the guard's direct IPv6), where deletes by key could half-fail and leave the old `Direct` open. Then the static sets change by key: on a disconnect the guard goes, and the kill switch too unless the toggle or the crash posture holds it. The next connect opens a new dynamic session.
- **Leaks:** between the drop and the close, as on every OS (live flows: [crash posture](#crash-posture-boot-session-recovery)). A close that errs still drops the handle; if enumeration then finds a dynamic filter of ours, the agent exits non-zero and BFE ends the session as after a crash, under a second later. A0 proves both deletions.
- **Blocks:** between the close and the static change, the down shape plus the guard's static set (global IPv6 and the overlay refused), also after a failed static change until the next tick; under the "space" preset with the toggle off, a tunnel drop keeps the guard without its direct IPv6 permits until the reconnect.

Removing an owner while up deletes its static set in one transaction, then its dynamic permits by key, then its sublayer and provider: each state is wider than the last, and the target has no such owner.

**Watches.** Each owner subscribes (`FwpmFilterSubscribeChanges0`) to its own provider's filters only; a notification triggers a re-apply under the lock, a compare that writes only differences. Neither owner writes the other's objects, so the watches can't undo each other, and an owner's own writes end in a compare that finds nothing.

**Engine errors** are exactly a dead handle (`ERROR_INVALID_HANDLE`), `RPC_S_SERVER_UNAVAILABLE` and `FWP_E_SESSION_ABORTED`: what a BFE stop or crash produces, with every object, session and subscription gone [17][33]. On one the adapter drops both sessions, reopens with backoff, re-subscribes, and re-applies each owner's last wanted set at once, not waiting for the keeper (its skip, `killswitch.go:236`, would leave 5 s unenforced). Any other error (`FWP_E_TIMEOUT` behind another product's transaction, a conflict) fails that change alone, so a slow neighbour never drops a connected member's TUN permits. While BFE is down nothing is enforced (RR81).

**Lost.** *Dynamic only* (wireguard-windows [8]): the kill switch vanishes on a crash. *Persistent* (Mullvad [15]): closes the boot window (RR80) but outlives a broken install (question 10). *Boot-time filters*: until BFE starts, useful only with persistent ones [18].

## Service

**Decision.** A service `thinkpol`, LocalSystem, made through `sc.exe` behind the `Runner` (`sc create`, `config`, `failure`, `failureflag`, `sidtype`, `sdset`) [20][34]. `Render` produces the canonical `sc qc`, `sc qfailure` and `sc qfailureflag` text, which install compares with what `sc.exe` reports: a hand-edited service is `ErrDefinitionChanged`, as for systemd.
- ImagePath `"%ProgramFiles%\thinkpol\thinkpol.exe" up -service`; start **automatic, not delayed** (delayed widens the boot window); dependencies `BFE`, `Nsi`, `Tcpip`; service SID unrestricted.
- **Restart:** `actions= restart/5000`, reset after a day, `failureflag 1` (an error exit restarts too). The last action repeats [44], so there is no start limit, as security.md wants; A0's throwaway service dies four times. Recovery runs only when the process ends without reporting STOPPED, or reports it with a non-zero code under that flag [20].
- **Start:** the agent reports RUNNING once it holds the host lock, **before** the node starts: a slow connect is then not a start timeout (about 30 s), which SCM doesn't treat as a failure. Its first engine open backs off until BFE answers: BFE reports RUNNING before its RPC interface does, and a start that failed on it would count toward `restart_loop`.
- **Stops restart.** Every stop but a shutdown exits with a non-zero service code unless install, uninstall or update marked it intended (a marker in `run\`, stamped with the boot session), so any stop is followed by a restart 5 s later; to keep it stopped, disable it first ([recovery](#recovery-runbook-wording)). The reason is BFE: `net stop bfe` stops its dependents first, thinkpol among them, while BFE still runs, and the agent can't tell that stop from another; the restart starts BFE again. A0 proves the order with a throwaway service, C the restart; failing that, the tray starts the service (question 15).
- **Shutdown.** Stop and preshutdown are accepted, at Windows' default 10 s preshutdown timeout [35]; a stop cut short aborts any WFP transaction in flight, leaving the static set whole.
- **A stop leaves the down shape** ("a stop is not a disconnect"). The tray: [desktop-client.md](desktop-client.md#the-local-api); Windows adds that the service's DACL grants the access group start, query-status and interrogate (question 15).

**Fast Startup.** Windows' default "Shut down" hibernates the kernel session; "Restart" and `shutdown /s` don't [21]. A Fast Startup power-on is expected to keep the process, static objects, boot key, adapter and routes (no connect-on-boot); A0 proves which survive.

**Lost.** A scheduled task (no restart or stop semantics); NSSM, WinSW (a third-party SYSTEM binary in front of ours); `svc/mgr` (API calls, no definition to compare).

## Crash posture, boot session, recovery

**After a crash** static objects stay and dynamic ones go: the kill switch's down shape (toggle on or crash posture) plus the guard's static set, as rule 7 wants. So **new** flows to direct destinations, DNS off the TUN, IPv6 beyond link scope and the overlay are refused at once. Live flows may not be: ALE authorizes a flow once, at its start. Until A0 shows live flows stop when their permit goes or a block arrives, only new flows are claimed (RR18; plan B otherwise). SCM restarts the agent in about 5 s; its start-time cleanup narrows to the down shape, clears recorded routes, then connects if the boot's record says so.

**Restart loops** are **three starts within ten minutes**, for agent and tray alike. The agent counts starts in the boot's connect record and puts `restart_loop` in health. An agent dying in its first second never serves it, so while the pipe is absent the tray counts process-ID changes in SCM's status (query-status), shows the one-step recovery, and doesn't start a looping service (question 15). Nothing more goes to disk (S2).

**Boot session.** `%ProgramData%\thinkpol\run` survives restarts, so records carry a boot session: a random nonce in the volatile key `HKLM\SOFTWARE\thinkpol\Boot`, gone at the next real boot. `REG_OPTION_VOLATILE` doesn't change an existing key [36], so the agent takes a new nonce only on `REG_CREATED_NEW_KEY`, and checks an existing key with a non-volatile probe subkey, which a volatile parent refuses (`ERROR_CHILD_MUST_BE_VOLATILE`) [36]; a non-volatile key is deleted and made anew, and health reports it.

**Rollback** is `thinkpol rollback` in an elevated terminal: exit 75 while the host lock is held; it records the boot disconnected and runs `ClearHost` (recorded routes, the TUN's DNS values, both providers' objects), then reports what's left. `KillSwitchPlace` names the WFP sublayer `thinkpol-killswitch`. Two cross-OS additions (TP-W5): `-kill-switch-off` also writes the toggle off in the device file, so the next start comes up disconnected with nothing in place; and `-wait` retries the host lock for up to 15 s, which a start that dies at once holds for under a second.

**Exit codes** keep their numbers: `ERROR_ACCESS_DENIED` on a named input is 77; no pipe (`ERROR_FILE_NOT_FOUND`) is `service_down`, 69; `ERROR_PIPE_BUSY` after retries is 75.

**Crash trace.** SCM gives a service no stderr, so the agent opens `crash-trace` (SYSTEM and Administrators only) and passes it to `debug.SetCrashOutput`; `up` writes its exit error there.

**The stop note** (`KillSwitchStopNote`, `killswitch.go:78`) gets Windows wording in TP-W5: "a stop leaves the kill switch in place, as a crash does, and the service restarts in 5 s: only the entries (and the LAN with allow-LAN, its DNS refused) are reachable, and no names resolve, until the agent runs again; to stop with traffic going direct, run `thinkpol kill-switch off` and `thinkpol disconnect` first; to get the network back without it, use Start → thinkpol: restore network".

### Recovery (runbook wording)

- **One step, for any member** (the agent dies at each start, toggle on or off): Start → **thinkpol: restore network**, then accept the administrator prompt. Install (TP-W7) makes the shortcut; elevated, it runs the by-hand steps below: disable, kill (a hung start holds the host lock past `-wait`'s 15 s), then `rollback -kill-switch-off -wait`. The network is back and the service stays disabled until someone fixes it, re-enables it and turns the kill switch on.
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

**Pipe.** `\\.\pipe\ProtectedPrefix\Administrators\thinkpol\api`, the `-api-socket` default. The session manager's `ProtectedPrefix\Administrators` lets only administrators and SYSTEM create pipes beneath it, so no standard user can squat the name while the service is down; Tailscale's daemon pipe lives there [23][37]. go-winio [22] serves it: it always rejects remote clients, creates the first instance exclusively, and exposes the handle (`Fd()`).

**Every instance carries the DACL.** go-winio v0.6.2 passes the descriptor only for the first handle (`pipe.go:344-371`, `:416-417`). A0 checks the DACL and owner SYSTEM on a second connection; if either differs, our own listener passes it to every instance.

**A failed Listen isn't fatal** (a name taken in the restart gap, under the prefix only by an administrator): the data plane keeps running, Listen retries with backoff, and health reports `local_api_unavailable` (log and diag; the tray sees `service_down`). A fatal Listen would make a squatted name a restart loop.

**DACL** (protected; `O:SY`): SYSTEM and Administrators full; the access group `FILE_READ_DATA`, `FILE_WRITE_DATA`, `FILE_READ_ATTRIBUTES`, `READ_CONTROL`, `SYNCHRONIZE`, and nothing else. Never generic write: it includes `FILE_APPEND_DATA`, which on a pipe is `FILE_CREATE_PIPE_INSTANCE`, and would let a member open a server instance beside the service [38]. Clients dial with exactly those rights at `SecurityIdentification` (`DialPipeAccessImpLevel`), since `DialPipeAccess` is anonymous (`pipe.go:272-273`) [22][23].

**The client checks the server on every connection**: `GetSecurityInfo` on its handle must show the owner SID SYSTEM. Opening the server process's token (`OpenProcessToken`) is denied to standard users for a SYSTEM process, so it can't be the check.

**The caller, per connection.** The server impersonates at Identification level (on a locked OS thread), reads the token's user, enabled groups and elevation, and reverts: the analogue of `SO_PEERCRED`. A failed impersonation (an anonymous dial) is no one, never `Root`.

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

Layers: C = `ALE_AUTH_CONNECT`, R = `ALE_AUTH_RECV_ACCEPT`, F = `IPFORWARD` (ICS, the hotspot, WinNAT if it uses it: A0), each V4 and V6 unless marked. R matters because replies to accepted inbound connections never meet C. F is per packet and has no protocol or port conditions [43], so there a block drops rather than refuses. `FWP_UINT8` weights; the highest match in a sublayer decides.

| W | Kill switch | Layers | Session |
|---|---|---|---|
| 15 | permit loopback | C R | static |
| 14 | permit the agent: app ID of the installed `thinkpol.exe` **and** user LocalSystem | C R | static |
| 13 | permit the TUN: by its LUID; on F two filters, leaving by it and arriving from it | C R F | dynamic |
| 12 | **block** `Dnscache` (service-SID descriptor) to unicast and broadcast destinations (the two address types consecutive, so they OR), any port; only while it runs alone | C | static |
| 11 | **block** DNS (UDP, TCP 53, 853) to anywhere | C | static |
| 10 | permit `Allow` (entries; the LAN with allow-LAN); on F the entries only: to them, and from them to the LAN ranges | C R F | static |
| 9 | permit `Direct`; on F to it, and from it to the LAN ranges | C R F | dynamic |
| 8 | permit DHCPv4: local 68 → remote 67, and inbound from 67 to local 68; DHCPv6: 546 → 547 at `ff02::1:2`, and inbound from 547 to local 546 | C R | static |
| 7 | permit ND 135/136 to and from **anywhere**; RS 133 to `ff02::2`; RA 134 and redirect 137 from `fe80::/10`; MLD 130–132, 143 to multicast | C6 R6 | static |
| 0 | **block** all | C R F | static |

| W | Guard | Layers | Session |
|---|---|---|---|
| 15, 14 | permit loopback; permit the agent (as above) | C R | static |
| 13 | permit the TUN (as above) | C R F | dynamic |
| 12 | **block** `Dnscache` (as above) | C | static |
| 11 | **block** DNS (53, 853) | C | static |
| 10 | **block** the overlay's networks (its IPv4 range and ULA) | C R F | static |
| 9 | permit `Exempt.Direct`'s IPv6 part; on F6 to it, and from it to the LAN ranges | C6 R6 F6 | dynamic |
| 8 | permit link-scoped: ND as above, DHCPv6 as above, `fe80::/10`, `ff02::/16` | C6 R6 | static |
| 0 | **block** IPv6 | C6 R6 F6 | static |

- `Mark`, `NoDNS` and `Upstreams` (kill switch) and `Mark` and `Upstreams` (guard) are ignored: the agent's permit covers them. The app ID is the installed path, which updates keep and only Administrators can write.
- **Forwarding (F)** mirrors `forwardRules` (`killswitch_linux.go:590-612` at `0743eef`), in order:

  | Linux | F | Can't be said, and what changes |
  |---|---|---|
  | `oifname` TUN, `iifname` TUN (:594) | 13, two filters: egress `IP_FORWARD_INTERFACE` = its LUID; arrival `SOURCE_INTERFACE_INDEX` = its index [43][45] | nothing (one filter would AND them) |
  | a bridge to itself (:596-598) | none | a Hyper-V switch is layer 2, never routed by the host (RR82) |
  | `noDNS` (:599) | none | no ports on F: down, DNS to an entry on the LAN passes (RR91); `NoDNS` is empty while connected (`agent/killswitch.go:152-155`) |
  | `Allow`, `Direct` by destination (:600) | 10 the entries; 9 `Direct` | `Allow`'s LAN is left out, its DNS unrefusable: no LAN address but the entries |
  | by source, `ct direction reply` (:605-610) | 10, 9: from the set to the LAN ranges (`firewall.LAN`) | no direction: not replies only (below) |
  | reject (:611) | 0 block | dropped, not refused |

  So a routed client reaches the TUN and back, the entries and `Direct` (any port, DNS included, as Linux while connected), no other LAN address, allow-LAN or not. Keeping LAN entries off F while down would split the static entry permit, only to stop lookups reaching our own server; RR91 records it. A crash or the down shape drops forwarded `Direct` at once (F is per packet).
- **Replies and NAT.** ICS and hotspot replies arrive addressed to the machine, so F can meet them only after translation, with the client's address; no Microsoft page says where ICS or WinNAT translate; A0 records it (plan B). The source filters are no reply match: without NAT (question 17c) they pass any packet from an entry or `Direct` (the domestic ranges under "all but domestic") to a LAN address, unsolicited too, carrying nothing of a client's out (RR91). The destination stays, as "from the set" alone would let out a client whose address is in it. Whether forwarding meets F at all is A0's (question 17; else RR82, RR91).
- **Address sets** are one filter with consecutive remote-address conditions: conditions AND, but "consecutive conditions with the same fieldKey will be evaluated using the OR operator" [41] (noted since Windows 7), as wireguard-windows relies on [42]; A0 sends a packet to each of a two-address filter's addresses. If 10,000 don't fit one filter (A0 times it), the set is chunked into filters of at most N at the same weight and action. F's "from the set to the LAN ranges" is one filter: sources ORed, destinations ORed, the two ANDed.
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
| RR90 | A restart loop (Windows) | the agent dies at every start; SCM restarts it every 5 s without limit (its last action repeats [44]) | toggle on: no network but the entries; toggle off: IPv4 by address only, no names (the guard's static DNS block) | — | fails closed; one step out (restore network: disable, kill, rollback `-kill-switch-off`), after which the service stays disabled until re-enabled; the tray infers the loop from SCM | TP-W5, TP-W7 |
| RR91 | Forwarded traffic (Windows) | the kill switch in place while the device forwards (hotspot, ICS, WinNAT) | down, a routed client's DNS to an entry on the LAN (Linux refuses it); packets from an entry or `Direct` to a LAN address, not only replies | R4 | F has no ports or direction; routed clients reach the TUN, the entries and `Direct`, no other LAN address (question 18); guard alone or switch off: IPv4 as on Linux; a crash or the down shape drops `Direct` at once (per packet); unproven without forwarding (question 17) | TP-W2b |

The earlier draft's squatted-pipe row is gone: only administrators can create a pipe under the protected prefix, and a failed Listen isn't fatal.

Existing rows: RR17's Windows half closes; RR44 drops Windows; RR18 gains "Windows: new direct flows refused at once (live ones per A0); names refused until restart or rollback"; RR62 gains "Windows: DNS to the LAN, and `Dnscache` to any unicast address, is refused in both shapes (RR88); forwarded clients reach no LAN address but the entries (RR91)"; RR58 (the kill-switch repair window, the RR58 TP-217 keeps) gains Windows' window of about a second; RR59 points to RR80; RR3, RR7, RR15, RR21–RR23, RR43 and RR51 gain Windows wording.

## Appendix: sources

Checked 2026-11-15 (43 and 45: 2026-11-16).

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
41. Microsoft, `FWPM_FILTER0`: <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0>
42. wireguard-windows `rules.go:479,999` at `704675c33561`: <https://github.com/WireGuard/wireguard-windows/blob/704675c33561/tunnel/firewall/rules.go>
43. Microsoft, conditions at each layer: <https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer>
44. Microsoft, `SERVICE_FAILURE_ACTIONS`: <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw>
45. Microsoft, filtering condition identifiers: <https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers->
