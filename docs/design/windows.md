# thinkpol-vpn — Windows design

How a device meets the macOS and Linux contract on Windows (M5: TP-047, the data plane; TP-076, the kill switch). A design for review; nothing here is built. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md), `RR-Wn` rows proposed [below](#proposed-residual-risks); `[n]` are [sources](#appendix-sources).

The behaviour to match is decided:
- [security](security.md#kill-switch): the kill switch, the crash posture, rollback;
- [routing](routing.md): the route table, DNS;
- [desktop client](desktop-client.md): the local API's two gates and codes;
- [configuration](configuration.md): the node and device files;
- TP-167's [exit codes](api-overview.md#tp-167-exit-codes-and-the-setting-shape).

**Testing.** The owner proves Windows on one real device only: no CI runners and no VMs (owner, 2026-11-15). So each adapter has two halves:
- a pure half (rule rendering, layouts, policies), unit-tested with fakes on every OS (`make lint` already vets `GOOS=windows`);
- a thin OS half, proven by device checks. These run as a test binary built on the development machine (`GOOS=windows go test -c -tags windowsdevice`) that the owner runs elevated. It prints evidence and undoes what it changes.

## Seams

Windows code goes in `_windows.go` files of the package that owns each seam. Today an `_other.go` stub refuses there. `cmd/thinkpol/platform.go:17` (`platform()`) only wires; Windows gets `platform_guard_windows.go` beside `platform_guard_other.go`. KRN-001 (done) lets grpckit serve any `net.Listener`, so a pipe listener needs nothing from the kernel.

| Seam | Port (file:line) | Windows provides |
|---|---|---|
| TUN | `tun.Create` `internal/dataplane/tun/tun_other.go:11`; `WorkerHost.NewTUN` `internal/agent/platform.go:31` | a Wintun `wgtun.Device`; `DefaultName` |
| Addresses, routes | `netcfg.Configurator` `internal/dataplane/netcfg/netcfg.go:547` (contract above it), `New` `netcfg_other.go:14`, `Clear` `netcfg.go:435` | Apply all-or-nothing, DefaultRoute, Watch, Survey, Close; one per owner; ownership by LUID and record |
| Route table | `routetable.New` `routetable.go:428`, `LayoutOf` `split.go:31`, `SplitRoutes` `split.go:82`, `SocketControl` `control_other.go:10` | macOS's split layout without reject routes; sockets bound with `IP_UNICAST_IF` |
| Leak guard | `routetable.Guard` `internal/dataplane/routetable/guard.go:20` | a WFP sublayer; `firewall.InspectIPv6Guard` |
| Kill switch | `agent.KillSwitch` `internal/agent/killswitch.go:23`; `firewall.KillSwitchRules` `internal/dataplane/firewall/killswitch.go:17`; `KillSwitchPlace` `killswitch_other.go:6` | a WFP sublayer; `firewall.InspectKillSwitch`; one new rules field (`LANDNS`, below) |
| DNS | `dns.System` `internal/dataplane/dns/resolvconf.go:48`; `SetSystem`/`RestoreSystem`/`SystemUpstreams` `system_other.go:13-22`; `Inspect` `inspect_other.go:11` | DNS on the TUN interface; `Problem`; the uplinks' resolvers |
| Platform | `agent.Platform` `internal/agent/platform.go:84`, `DeviceHost` `:50`, `ClearHost` `:112`; `supported` `supported_other.go:13` | device mode only; server mode refused |
| Host lock | `HostLock` `internal/agent/hostlock_other.go:7` (Unix: `hostlock_unix.go:18`) | `LockFileEx`, released by the OS when the process dies |
| Connect record | `ConnectRecord` `internal/agent/connectrecord.go:15`; `HostConnectRecord` `connectrecord_other.go:9` | a file stamped with Windows' `BootSession` |
| Trusted dirs | `trusteddir.Open` `internal/dataplane/trusteddir/trusteddir.go:19`, `BootSession` `boot_linux.go:17` | owner SYSTEM or Administrators, no foreign write ACE, no reparse point |
| Crash trace | `fixCrashTraceFile` `internal/agent/crashtrace_other.go:11`, `detachStderr` | the agent opens it and calls `debug.SetCrashOutput` |
| Service | `service.System` `internal/agent/service/install.go:26`, `Installer` `:57`; `HostInstaller`/`CheckRoot`/`InstallingUser` `host_other.go:13-21`; `HostDropIns` `systemd.go:162` | an SCM `System` (`x/sys/windows/svc/mgr`) behind the `Runner` port |
| Local API | `Listen` `internal/agent/localapi/listen_other.go:12`; `callerOf` `peercred_other.go:12`; `Caller` `auth.go:68`; `Policy` `auth.go:85`; `Dial` `client.go:47` | a named pipe; `Caller` gains a Windows identity (the one seam change) |
| Rollback | `agent.Rollback` `internal/agent/rollback.go:73` | unchanged, run elevated |
| Diag | `agent.Inspector` `internal/agent/diagnose.go:84`; TP-133 (its branch) | readers for WFP, routes, DNS, the service |

## TUN

**Decision.** Wintun through `golang.zx2c4.com/wireguard/tun` (`CreateTUNWithRequestedGUID`; already a dependency), with a GUID derived from the name. A stable GUID keeps the LUID, the interface's registry key and its firewall profile the same across runs. `wintun.dll` lives beside `thinkpol.exe` [1][2]; `DefaultName` is `thinkpol`.

**Lost.**
- *WireGuard-NT*: kernel WireGuard owns its UDP socket, so the path layer and the transports can't sit under it (rule 1).
- *tap-windows6*: layer 2, its own driver to sign.
- *A driver of our own*: kernel code.

**Contract.** One real TUN for the router, as utun; netcfg sets its addresses and MTU (`OwnerOverlay`).

**Unit tests.** GUID derivation.

**Device.** Traffic flows both ways. Does a killed process's adapter disappear? Wintun documents that `WintunCloseAdapter` removes it and has a cleanup for orphans, but says nothing of a crash [2]. ClearHost removes any leftover adapter of our pool.

## Addresses and routes

**Decision.** `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg` (MIT; wireguard-windows and Tailscale use it [3]) behind a `netcfg` adapter. Windows has no policy routing, so it uses **macOS's layout**, `SplitRoutes`:
- `0.0.0.0/1` and `128.0.0.0/1` go into the TUN;
- the IPv6 `/2`s go into the TUN;
- direct prefixes and endpoints go via the default gateway;
- foreign routes over tunnelled space are shadowed by more specific ones. Windows honours DHCP option 121 (TunnelVision) and RA route options.

**No reject routes on Windows.** The layout's `::/1`/`8000::/1` and overlay rejects can't be expressed. Two things replace them:
- While the TUN exists, the IPv6 halves go into it even when the overlay is IPv4-only, and the router refuses what the TUN can't carry ("what the TUN can't take is refused").
- Once the TUN is gone, the [guard](#the-ipv6-guard) refuses IPv6 and the overlay's networks off the TUN.

`LayoutOf` gains a no-rejects switch, tested on every OS.

**Ownership.** Routes on the Wintun LUID are the overlay's. Direct and endpoint routes on the uplink carry no owner tag on Windows, so they are kept in a route record per owner, stamped with the boot session, as on macOS (`record_darwin.go`; corrupt records follow RR53).

**Links bypass the tunnel by socket.** `SocketControl` sets `IP_UNICAST_IF`/`IPV6_UNICAST_IF` to the default route's interface as each socket opens, as wireguard-windows does [4]. Endpoint routes stay too, as on macOS.

**Watch.** `NotifyRouteChange2`, `NotifyIpInterfaceChange` and `NotifyUnicastIpAddressChange`, coalesced.

**Big tables.** OpenVPN users report about 27k routes taking very long, with nothing forwarded until done [5]; no per-call cost is documented. So:
1. Apply diffs only. `winipcfg.SetRoutes` flushes first [3], so the route table doesn't use it.
2. Direct routes go in after the TUN's ("direct grows after"). Meanwhile direct destinations go through the tunnel: slow, never a leak.
3. TP-W3 measures 1k and 10k routes. If that is too slow, the fallback is to cap direct routes and tunnel the smallest prefixes, said in health (question 7). Narrowing direct is always safe.

Unknown: whether `CreateIpForwardEntry2` routes are active-store only (the cmdlets write both stores by default [6]). A device reboot settles it; the record lets the next start clear survivors.

**Lost.**
- *Copying winipcfg*: large and generated.
- *`route.exe`/`netsh`*: slow, parsed text, no events.
- *A WFP "route"*: WFP doesn't route; redirecting needs a callout driver.

**Unit tests.** Golden layouts without rejects; diff planning; the record; ownership on fake surveys.

**Device.**
- Apply and Close leave the table as found.
- 1k/10k timings.
- A bound socket leaves by the uplink while `0/1` is in the TUN.
- Wi-Fi changes, sleep.

## DNS

**Decision.**
1. Point Windows at the node's resolver **on the TUN interface**: its DNS servers are the resolver's overlay addresses, it gets the lowest interface metric, and the DNS client's cache is flushed on connect and on each map or rule change.
2. **Block DNS elsewhere with WFP** in the guard's sublayer: while connected, UDP and TCP 53 and 853 off the TUN are refused for every process but the agent. This is OpenVPN's `block-outside-dns` mechanism and wireguard-windows' [7][8].

The block is required. Smart multi-homed name resolution sends each query to every interface's servers at once. Its policy switch only serialises the queries, and isn't always honoured [9].

**Lost.**
- *NRPT `.` rule* (Tailscale uses NRPT for split DNS [10]):
  - any Group Policy NRPT rule makes Windows ignore every local one [10][11];
  - it is registry state that outlives a crash, while interface DNS goes with the adapter;
  - it doesn't stop the multi-homed queries, so the block is needed anyway.
- *Disabling multi-homed resolution*: incomplete [9] and machine-wide.
- *Rewriting the uplinks' DNS*: other software's state, and a restore after a crash.

**Upstreams.** `SystemUpstreams` reads, through `GetAdaptersAddresses`, the DNS servers of the interfaces holding a default route, excluding the TUN. Direct queries leave from the agent bound to the uplink and pass the block by app ID.

**`Problem()`** reports unprotected when:
- Group Policy NRPT rules exist (their names are refused by the block: they fail, not leak);
- the interface write failed;
- the block isn't enforced.

Stale and no-upstream are reported as on the other OSes.

**`RestoreDNS`.** Nearly nothing to restore: the setting is the adapter's. It removes the TUN's DNS registry values if the adapter is gone.

**Outside.** Windows 11's DNS client can use DoH to known servers [12], and apps run their own DoH. Both are port 443 traffic (RR3). LLMNR, mDNS and NetBIOS stay the LAN's (RR7); NetBIOS over TCP/IP is off on the TUN.

**Unit tests.** The guard's DNS filters; `Problem` on a fake registry.

**Device.**
- `pktmon` shows no 53/853 on the uplink during `Resolve-DnsName` [13].
- The cache is flushed.
- A GP-NRPT machine reports unprotected.

## The IPv6 guard

**Decision.** The guard (`routetable.Guard`, the connection's firewall owner) is the WFP sublayer `thinkpol-guard`, applied and removed with the routes. At the ALE connect and receive-accept layers it refuses, off the TUN and loopback:
1. **IPv6**, except to `Exempt.Direct`'s IPv6 part, the endpoints, `routetable.LinkScoped` (ND, DHCPv6, MLD) and the agent's sockets: Linux's guard;
2. **DNS** (53, 853), except from the agent: [above](#dns);
3. **the overlay's networks** (its IPv4 range and ULA): the reject routes Windows lacks.

**Crash.** Rule 7 says the guard outlives the agent. Its blocks and its endpoint and link-scoped permits are in the **static** session; the direct and upstream permits are in the **dynamic** one ([below](#two-sessions)). After a crash, IPv6 passes to the entries only, the overlay is refused, and DNS off the TUN is refused. So names fail until the restart or `rollback`: stricter than RR18's Linux wording.

**Transition tunnels and RAs.** Microsoft disables ISATAP and Teredo by default; 6to4's default is unclear [14]. Their IPv6 is on interfaces that aren't the TUN, so rule 1 refuses it. A rogue RA's routes and RDNSS servers meet the split routes and rules 1–2. Nothing changes machine-wide IPv6 settings.

**Lost.**
- *Disabling IPv6 on adapters* (`DisabledComponents`): machine-wide, outlives an uninstall, some bits need a reboot.
- *Leaving it to the kill switch*: the guard is always on while connected; the kill switch is a toggle.

**Unit tests.** Golden filter sets per `Exempt`, split by session.

**Device.**
- `ping -6 -S` and `curl -6 --interface` on the uplink are refused while connected and after `taskkill /F`.
- Direct IPv6 passes only while connected.
- ND keeps the uplink working.

## Kill switch (WFP)

It implements `agent.KillSwitch` with TP-048's shapes. The agent picks the shape; the firewall only applies it.

### Objects

- **Provider** `thinkpol` (fixed GUID): enumerating by provider finds every object of ours, a crashed run's included.
- **Sublayers** `thinkpol-killswitch` and `thinkpol-guard`, both at weight `0xFFFF`, the maximum, as wireguard-windows and Mullvad use [8][15]. There are two because a packet must pass both owners. WFP evaluates every sublayer, and a block in any of them beats permits elsewhere unless a permit is *hard* [16].
- **Layers.** `ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT_V4/V6`. Receive-accept is filtered because Linux's output chain refuses replies to accepted inbound connections, and those never meet the connect layer. wireguard-windows filters both [8]. ICS is filtered at `IPFORWARD_V4/V6`.
- **Every permit of ours is soft** (no `CLEAR_ACTION_RIGHT`). A hard permit would override the other sublayer's block [16].

### Two sessions

| Session | Holds | When the agent dies |
|---|---|---|
| **static**: non-dynamic, no `PERSISTENT` flag | provider, sublayers, and the **down shape**: loopback, the agent, NoDNS, `Allow` (entries; LAN with allow-LAN), DHCP, ND, block-all. Also the guard's blocks and its endpoint and link-scoped permits | stays, until a start replaces it, rollback removes it, or the machine restarts |
| **dynamic**: `FWPM_SESSION_FLAG_DYNAMIC`, one per agent life | the **connected shape's additions**: the TUN, `Direct`, the upstreams, DNS to the LAN with allow-LAN; the guard's direct permits | deleted by BFE when the session ends, a crash included [17] |

What WFP guarantees here:
- Dynamic objects go when the process ends, however it ends [17].
- Persistent objects survive reboots and are re-added from the registry at BFE start [17][18].
- Static objects survive the process and go when BFE stops, which is at a restart.
- A dynamic filter in a static sublayer is the permitted direction: persistent objects may not reference non-persistent ones, not the reverse [17]. TP-W2's first device check confirms it.

**The static set is always the down shape**, so the port gains one field. `KillSwitchRules.LANDNS` is the NoDNS set the down shape would have (the LAN with allow-LAN), given in both shapes. Windows blocks it statically and lifts it with a dynamic permit while connected. Linux and macOS ignore it.

**Why.** It meets the crash posture and narrows two residuals:
- **A crash or a stop leaves exactly the down shape.** The dead agent's direct destinations go at once; Linux expires them in 30 s and macOS keeps them (RR18).
- **A crash refuses DNS to the LAN at once.** RR62's crash gap, where the connected shape lets the LAN's resolvers get lookups until the restart narrows it, doesn't exist here.

**Lost.**
- *Dynamic only*, as wireguard-windows [8]: the kill switch would vanish on a crash, the opposite of the crash posture.
- *Persistent*, as Mullvad's blocking state [15]: closes the boot window (RR-W1), but a persistent block outlives a failed uninstall, a deleted folder or a broken binary. The machine would stay offline across reboots, with no obvious Windows tool to clear it. With static objects **a restart is always a way out**, as with nftables and pf. This is question 3.
- *Boot-time filters*: enforced only from tcpip.sys start until BFE starts, and the flag is restricted [18]; useful only paired with persistent filters, so they are the same question.

### Filters and weights

`FWP_UINT8` weights (0–15): the highest match in our sublayer decides.

| W | Kill-switch filter | Session | Shape |
|---|---|---|---|
| 15 | permit loopback (`IS_LOOPBACK` flag) | static | both |
| 14 | permit the agent: app ID of `thinkpol.exe` **and** user LocalSystem | static | both |
| 13 | permit the TUN (local interface = its LUID) | dynamic | connected |
| 12 | permit DNS (53, 853) to `LANDNS` | dynamic | connected |
| 11 | **block** DNS (UDP, TCP 53, 853) to `NoDNS` ∪ `LANDNS` | static | both |
| 10 | permit `Allow` | static | both |
| 9 | permit `Direct`; the upstreams on their ports | dynamic | connected |
| 8 | permit DHCPv4 (68→67), DHCPv6 (546→547 to `ff02::1:2`, `fe80::/10`) | static | both |
| 7 | permit ND (ICMPv6 133–137) to `fe80::/10`, `ff02::/16`; MLD (130–132, 143) to multicast | static | both |
| 0 | **block** all | static | both |

- **The agent's permit is Windows' socket mark.** ALE knows the process, so links and direct DNS pass without a mark, an entry on the LAN on port 53 or 853 included (Linux passes it by mark; macOS can't). It is wider than a mark: any socket of the agent passes (RR-W4). The app ID is the path, so updates keep the path, and only Administrators can write there.
- **Address sets** are one filter each with OR-ed remote-address conditions (same-field conditions OR, different fields AND), never a filter per prefix. TP-W2 times 10,000 conditions.
- **Refused, not dropped.** An ALE block fails `connect` at once.
- **What WFP can't match.** No hop limit at ALE, so ND and MLD are limited by destination (RR-W5, RR13's counterpart). Kernel-generated ND may never meet ALE; wireguard-windows permits it anyway [8], and the device run shows which.
- **Interface-bound sockets** (RR21) meet the same filters: ALE runs whatever routing chose.
- **Hyper-V guests** (WSL2, Windows Sandbox, Docker on Hyper-V) bypass WFP's layer-3 filters, seen only as layer-2 frames [19]: RR-W3, RR61's counterpart.

### Apply, watch, close

The agent's logic (`internal/agent/killswitch.go`) is unchanged.
- **Apply.** The static set is replaced in one `FwpmTransactionBegin`/`Commit` (delete ours by provider, add the new set) and compared whole at every 10 s tick. The dynamic set follows in a second transaction. A failed transaction leaves what was there.
- **Watch.** `FwpmFilterSubscribeChanges0` on our provider re-applies within about a second of an outside delete (RR58).
- **Close.** Deletes every object of our provider from both sublayers, from any session.

### Other software

- **Defender Firewall**'s sublayers: its blocks beat our permits (a rule blocking `thinkpol.exe` takes the links down, and health shows it); our blocks beat its permits.
- **Another VPN's kill switch** blocks our entries and ours blocks its server: two can't both be on.
- **What passes around us:**
  - a hard permit in a sublayer evaluated first (equal 0xFFFF weights leave the order undefined);
  - a callout driver.

  `diag` lists other providers' 0xFFFF sublayers and hard permits at our four layers (RR-W2), as macOS's guard reports quick passes above its hook. A health code waits for device evidence.

### Tests

**Unit.** Golden (layer, weight, conditions, action, session) for:
- connected, down, allow-LAN, an entry on the LAN, an empty `Allow` while removed;
- re-apply idempotence and Close over a fake engine holding a crashed run's objects.

**Device** (TP-076's acceptance):
1. Kill switch on, `taskkill /F`: only entries (and the LAN, DNS refused, with allow-LAN) answer; the same after `sc stop`.
2. "Everything", toggle off, crashed: the same until the restart connects.
3. A disconnect with the toggle off removes it; on, it stays.
4. Static objects survive the kill and go at a restart; dynamic ones go at the kill (`netsh wfp show filters`).
5. An outside delete is back within a second.
6. Defender on: links up.

## Service and connect-on-boot

**Decision.** A service `thinkpol` created through `x/sys/windows/svc/mgr`, running as LocalSystem:
- ImagePath `"%ProgramFiles%\thinkpol\thinkpol.exe" up -service`, with no settings in it;
- start **automatic, not delayed**: delayed start begins about two minutes after boot and would only widen the boot window;
- dependencies `BFE`, `Nsi`, `Tcpip`;
- service SID unrestricted.

**Restart.** One recovery action, "restart after 5 s" (`RestartAfterSeconds`), which SCM repeats for every later failure, with a reset period of a day. `FailureActionsOnNonCrashFailures` makes an error exit restart too [20]. That is `Restart=always` with no limit.

**Stop.** Stop and preshutdown are accepted, with `StopTimeoutSeconds` as the preshutdown timeout. A stop leaves the down shape ("a stop is not a disconnect").

**Connect-on-boot.** Unchanged: `device.json` decides a boot's first start; later starts follow the boot's connect record.

**Fast Startup.** Its "shut down" hibernates the kernel session; "Restart" doesn't [21]. Whether the service process survives Fast Startup is not clearly documented [21]. If it does, a Fast Startup power-on is no boot to the agent: the record, the static WFP objects and the boot session carry over, and connect-on-boot doesn't run. That is consistent, but members must know it. Device check.

**For the tray (TP-049).** The service offers the pipe, `WatchStatus` and the codes, and tells `service_down` (no pipe) from `not_running`. Its security descriptor gives the access group query and start rights, so the tray can start a stopped service without elevation (question 8). Stop stays the administrators'.

**Lost.**
- *A scheduled task*: no restart or stop semantics.
- *NSSM, WinSW*: a third-party SYSTEM binary in front of ours.

**Unit tests.** The SCM `System` over a fake: create; update (stop, host lock, start); recovery actions; a hand-edited service is `ErrDefinitionChanged`, as for systemd; uninstall's order.

**Device.**
- Install, restart and uninstall leave the machine clean.
- A crash restarts in about 5 s as left.
- Connect-on-boot is off by default, then on across a restart.
- Fast Startup.

## Crash posture and rollback

**After a crash** static WFP objects stay and dynamic ones go. The adapter and its routes probably go too ([TUN](#tun)); uplink routes stay, as on macOS. SCM restarts the agent in about 5 s. Its start-time cleanup narrows to the down shape (the static set already is), clears recorded routes, then connects if the boot's record says so.

**Boot session.** There is no tmpfs: `%ProgramData%\thinkpol\run` survives restarts, so its records carry a boot session, as on macOS. Windows' `BootSession` is a random nonce in a **volatile registry key** (`HKLM\SOFTWARE\thinkpol\Boot`), which lives in memory and is gone at the next real boot. Lost: the boot time (shifts with the clock) and the registry's `BootId` (undocumented).

**A restart clears** the static objects, the adapter, the boot session and probably the routes. So it is a way out needing no thinkpol, unless the toggle is on (the service restores the down shape). A Fast Startup shutdown is not a restart; the runbook says "Restart" by name.

**Rollback.** `thinkpol rollback` from an elevated terminal (`sudo` where Windows 11 has it), unchanged:
- exit 75 while the host lock is held;
- records the boot disconnected;
- runs `ClearHost`: recorded routes, an orphaned adapter, the TUN's DNS values, every WFP object of our provider;
- reports what is left.

`KillSwitchPlace`: "the WFP sublayer thinkpol-killswitch (provider thinkpol)". `NeedsRootError` names an elevated terminal.

**Exit codes** (TP-167) keep their numbers:
- `ERROR_ACCESS_DENIED` on a named input is 77;
- no pipe (`ERROR_FILE_NOT_FOUND`) is `service_down`, 69;
- `ERROR_PIPE_BUSY` after retries is 75.

**Crash trace** (S2's device exception). SCM gives a service no stderr, so the agent opens `crash-trace` itself (SYSTEM and Administrators only) and passes it to `debug.SetCrashOutput`, which gets the runtime's fatal output. `up` writes its exit error there. A Go panic exits rather than faults, so Windows Error Reporting keeps no dump. SCM's event-log entries (7031, 7034) name only the service.

**Unit tests.** `ClearHost` parts; the boot record over a fake registry; the exit-code rows.

**Device.** `taskkill /F`, then `rollback`:
- no thinkpol provider in `netsh wfp show filters`;
- `route print` as before `up`;
- no adapter;
- the next start comes up disconnected.

A restart with the toggle off brings the network back.

## Local API over a named pipe

**Decision.** `\\.\pipe\thinkpol-api`, the `-api-socket` default on Windows, through `github.com/Microsoft/go-winio` (MIT, no cgo) [22]. If go-winio hides the server handle that identification needs, it is a small listener on `x/sys/windows` instead (TP-W6 decides).

The two gates:
1. **The pipe's DACL** replaces the 0750 directory. It is protected, with full access for SYSTEM and Administrators, read/write for the access group's SID, and nothing for anyone else. `PIPE_REJECT_REMOTE_CLIENTS` refuses SMB clients [22].
2. **The caller's token, per connection.** On accept, the server impersonates the client at Identification level, reads the user SID, group SIDs with their attributes, and elevation, then reverts: the analogue of `SO_PEERCRED`. Clients dial at `SecurityIdentification`, because go-winio's default dial is Anonymous; Tailscale does the same [22][23].
   - "Root" is LocalSystem, or a token with Administrators **enabled** (elevated).
   - An unelevated administrator's Administrators group is deny-only, so they count as a member or no one.

**Seam change.** `Caller{UID, GIDs}` (`auth.go:68`) becomes a struct with an OS identity, so `Policy` asks root, service user and member of either kind, and its tests run on every OS.

**The client checks the server.** Before its first call it checks the pipe server is SYSTEM (`GetNamedPipeServerProcessId`, then the token's user). Otherwise a user process squatting the name while the service is down could tell the tray "connected". The service creates its pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so it fails loudly if the name is taken. Unix needs neither check: the root-owned directory does both.

**Group.** A local group `thinkpol`, made by install (`net localgroup` through the `Runner`, as `groupadd` is), and the installing user is added. Under UAC "over the shoulder" elevation the elevated user is the admin, so `InstallingUser` is the console session's user, and `-user` overrides it. Membership counts from the next logon (RR43). Network Configuration Operators lost: it also lets members reconfigure every adapter.

**Unit tests.** `Policy` over Windows identities (SYSTEM; elevated; deny-only admin; member; stranger); the SDDL; the server check against fake lookups.

**Device.**
- A member's `status` works; a non-member gets 77.
- An unelevated admin is refused `logs`.
- A squatted pipe makes the service fail and the CLI refuse it.
- The pipe is unreachable remotely.

## Diag

**Online.** `agent.Inspector` readers:
- **Interface**: winipcfg.
- **Routes**: `GetIpForwardTable2`, split into ours by LUID, ours by record, and foreign.
- **Guard and kill switch**: `FwpmFilterEnum0` by provider, per sublayer and session. WFP keeps no per-filter counters; the report already allows that. Also whether the dynamic session is present, and other providers' 0xFFFF sublayers and hard permits.
- **DNS**: per-interface servers, local and GP NRPT rules, the multi-homed policy, DoH settings.
- **DropIns**: becomes the SCM configuration as reported (ImagePath, start type, recovery, dependencies), flagged when it differs from what install writes. Windows has no drop-ins; this is how settings drift there.

`schema_version` stays 1: values only.

**Offline** (TP-133): the readers need no agent, so an elevated `diag` with the service dead writes the same snapshot. WFP enumeration is granted to admins; unelevated is 77.

**Evidence without thinkpol** (runbook): `netsh wfp show filters`, `netsh wfp show state`, `route print`, `Get-DnsClientServerAddress`, `Get-DnsClientNrptPolicy`, `Resolve-DnsName` (not `nslookup`, which ignores NRPT [10]), `pktmon` [13].

## Install and uninstall

Paths and ACLs (configuration.md's open question):

| What | Where | Access |
|---|---|---|
| binary, `wintun.dll` | `%ProgramFiles%\thinkpol\` | SYSTEM, Administrators write; checked like `BinaryPath`'s directory |
| state | `%ProgramData%\thinkpol\` (`node.json`, `device.json`, keys, `map.bin`, `blobs\`, `crash-trace`) | protected DACL: SYSTEM, Administrators only |
| runtime | `%ProgramData%\thinkpol\run\` (lock, connect and route records) | the same |
| boot session | `HKLM\SOFTWARE\thinkpol\Boot`, volatile | the same |
| local API | `\\.\pipe\thinkpol-api` | [above](#local-api-over-a-named-pipe) |

Any user may create folders in `%ProgramData%`. So a `thinkpol` folder someone else made first, or with a foreign write ACE, or a junction, is refused, never adopted: `trusteddir`'s rule.

**Install** (elevated) follows today's steps:
1. readiness;
2. copy the binary and DLL;
3. group and member;
4. the crash-trace file with its DACL;
5. stop the old service;
6. the host lock;
7. create or update the service and start it.

**Uninstall:**
1. stops and deletes the service;
2. takes the host lock and runs `ClearHost`;
3. removes the binary. A running `thinkpol.exe` renames itself aside and is deleted at the next restart (`MoveFileEx`).

The group stays, as on Unix, and so does the Wintun driver (shared).

**M5's installer.** TP-051 wants a terminal-free install. An MSI action or a self-elevating first run calls `service install`; the package format is TP-051's.

## Updates and signing

Only M5's needs.

- **Wintun.** `wintun.dll` is signed and its driver is Microsoft-signed on every architecture, so no test-signing mode is needed [1][24]. The prebuilt DLLs may be redistributed unmodified under their own licence, separate from the source's GPL-2.0 [24]. The build fetches the pinned zip by SHA-256 (never committed, like the lists' sources), embeds the target's DLL, and install writes it out (question 5).
- **Our binary is unsigned for M5.** A downloaded one carries the Mark of the Web: SmartScreen shows "Windows protected your PC" and UAC an unknown publisher. Defender sometimes flags Go binaries (`Wacatac`) [25]. That is a documented "Run anyway" on the owner's device. For members it is TP-051's decision:
  - EV no longer bypasses SmartScreen;
  - Azure Artifact Signing (about $10/month) builds reputation like OV and is open to individuals in few countries [26];
  - SignPath Foundation signs open source free [25].
- **Updates.** Reinstall keeps the path, so the app-ID permit lets the new agent's links out while it starts. A failed update leaves the down shape. Signed updates (PRD A9) come later.
- **Architectures.** Go has native `windows/arm64` [27], Wintun ships ARM64 [24], wireguard-windows ships ARM64 [28]. We build amd64 and arm64 natively; x64 under ARM64 emulation is unsupported (its DLL driving the ARM64 driver is unproven). `make lint` adds `windows/arm64`.

## Proposed residual risks

Numbered when their ticket lands:

| # | Residual | When | What leaks, to whom | Breaks | Why accepted | Ticket |
|---|---|---|---|---|---|---|
| RR-W1 | Boot window (Windows) | toggle on, from power-on to the first apply; not after Fast Startup if the service survives it | what the machine sends meanwhile goes direct | D4, R2 | static objects die at restart; persistent ones would outlive a broken install (question 3) | TP-W2 |
| RR-W2 | WFP software ahead of ours | a hard permit in a sublayer evaluated first; a callout driver | what it permits passes the kill switch and guard | D4, D6, R2 | WFP arbitration lets it; `diag` lists them | TP-W2 |
| RR-W3 | Hyper-V guests | WSL2, Sandbox, Docker on Hyper-V, VMs on a NAT or external switch | all their traffic leaves direct [19] | D4, D6, R2 | they bypass WFP's layer-3 filters; RR61's counterpart | TP-W2 |
| RR-W4 | App ID wider than a mark | kill switch or guard in place | any socket of `thinkpol.exe` as LocalSystem passes | R2 | ALE matches processes; the agent opens no other outbound socket by design; its path is admin-only | TP-W2 |
| RR-W5 | ND and MLD by destination | kill switch in place | ND types to link-local and link-scope multicast pass from any process | D4 | no hop limit at ALE (RR13's counterpart) | TP-W2 |
| RR-W6 | Slow direct routes | large direct sets | nothing: direct goes through the tunnel while routes install, or beyond a cap | — | narrowing direct is safe (question 7) | TP-W3 |
| RR-W7 | Group Policy NRPT | managed machines with NRPT rules | nothing: their names are refused, so they fail; health says unprotected | R4 | GP NRPT overrides local rules [11] | TP-W4 |
| RR-W8 | A squatted pipe | the service down | a user process may hold `thinkpol-api`; clients refuse a non-SYSTEM server, so it is reported, not trusted | — | pipe names can't be reserved | TP-W6 |
| RR-W9 | DHCP to anywhere (Windows) | kill switch in place | UDP 68→67 to any IPv4 address from any process that binds 68 (no privileged ports) | D4, R2 | RR60's reasoning; ALE can't tell the DHCP client's svchost from another | TP-W2 |

Existing rows:
- **RR17**'s Windows half closes.
- **RR44** drops Windows: the host lock exists.
- **RR18** gains "Windows: direct goes at once; names refused until restart".
- **RR62** gains "Windows: a crash leaves NoDNS at once".
- **RR58** gains Windows' repair window of about a second.
- **RR3, RR7, RR15, RR21–RR23, RR43, RR51** gain Windows wording.

## Ticket split

Eight tickets replace TP-047's scope list; TP-W2 is TP-076 (keep its id). Plan for 1.5–2x the sizes (past estimates ran about 2x optimistic). Three device sessions prove the riskiest parts first:
- **A**, after W2 and W3: WFP and routing semantics through the test binary, no agent;
- **B**, after W5: the data plane run by hand;
- **C**, after W7: the service and TP-076's acceptance.

| Id | Title | Size | Deps | Acceptance |
|---|---|---|---|---|
| TP-W1 | Windows build and device-test harness | S | — | lint for `windows/amd64` and `arm64`; `wintun.dll` by pinned hash, embedded; a `windowsdevice` test binary builds on a Mac; a runbook page for running it and collecting `netsh wfp`/`pktmon` evidence |
| TP-W2 | WFP kill switch and guard (TP-076) | L | W1 | unit: golden filters per shape, the session split, re-apply and Close on a fake engine. A: static survives `taskkill /F` and goes at restart; dynamic goes at the kill; a dynamic filter in a static sublayer; an outside delete back in ~1 s; Defender on; 10k-condition timing |
| TP-W3 | Wintun, netcfg and the route table | L | W1 | unit: layouts without rejects, diffs, records, ownership. A: adapter fate after a kill; apply and close leave the table as found; 1k/10k timings; routes over a reboot; `IP_UNICAST_IF` leaves by the uplink |
| TP-W4 | DNS on Windows | M | W2, W3 | unit: `Problem`, upstreams, the guard's DNS filters. B: `pktmon` shows no 53/853 on the uplink with multi-homed resolution on; cache flushed; GP NRPT reported |
| TP-W5 | Agent platform: state, lock, boot session, crash trace, rollback | M | W2–W4 | unit: `trusteddir` ACLs, boot record, `ClearHost`, exit codes. B: `up` by hand connects with rules, DNS, guard; toggles; `taskkill /F` then `rollback` restores the machine; a forced panic lands in the trace |
| TP-W6 | Local API over a named pipe | M | W1 (parallel) | unit: `Policy` over Windows identities, SDDL, server check. B: member allowed, non-member 77, unelevated admin refused root calls, squatter refused, no remote access |
| TP-W7 | Windows service: install, uninstall, connect-on-boot, recovery | M | W5, W6 | unit: SCM `System` on a fake. C: install, restart, uninstall clean; crash restarts in ~5 s as left; connect-on-boot off then on; TP-076's three items; Fast Startup |
| TP-W8 | Windows diag (online, offline) and device checklist | S | W7, TP-133 | unit: rendering from fake readers. C: elevated `diag` after a kill shows the leftovers; checklist in TP-047's Notes |

## Open questions for the owner

1. **Your machine.**
   - a) x64 Windows 11;
   - b) ARM64 Windows 11;
   - c) x64 Windows 10 22H2;
   - d) other.

   *Rec:* say which before TP-W1; only that architecture gets proven.
2. **Versions for M5.**
   - a) Windows 11 only;
   - b) 11, plus 10 22H2 built but unproven.

   *Rec: b.* Same APIs; 10 is past mainstream support.
3. **Boot window.**
   - a) static objects, gone at restart (RR-W1), so a restart is always a way out;
   - b) persistent down-shape filters while the toggle is on.

   *Rec: a* for M5; take b up with RR59's Linux and macOS fix as one ticket.
4. **WFP library.**
   - a) `github.com/tailscale/wf` (BSD-3, in production at Tailscale [29]) behind our adapter;
   - b) copy wireguard-windows' syscall layer (MIT);
   - c) our own on `x/sys/windows`.

   *Rec: a,* falling back to b if TP-W2's spike finds a gap.
5. **`wintun.dll`.**
   - a) fetched by pinned hash, embedded, written at install;
   - b) committed;
   - c) user downloads it.

   *Rec: a.*
6. **Signing for M5.**
   - a) unsigned, with SmartScreen and Defender steps in the runbook, decided in TP-051;
   - b) an OV certificate now;
   - c) apply to SignPath now.

   *Rec: a,* exploring c for TP-051.
7. **If 10k direct routes are slow.**
   - a) accept it: tunnelled meanwhile;
   - b) cap them and tunnel small prefixes, said in health;
   - c) no "all but domestic" on Windows.

   *Rec:* decide after session A; default a, then b.
8. **The tray may start a stopped service.**
   - a) yes, the group gets start and query rights;
   - b) query only.

   *Rec: a.* Starting only restores protection.
9. **Device sessions.**
   - a) three (A, B, C);
   - b) two (B and C merged).

   *Rec: a.* A proves the crash semantics before anything builds on them, in one short evening.

## Biggest risks

1. WFP behaviour only a device can prove: dynamic filters in a static sublayer, what ND meets at ALE, others' hard permits. Session A goes first.
2. Hyper-V guests bypass every layer-3 filter (RR-W3). WSL2 and Docker Desktop users get no kill switch for them, and the host can't report it.
3. Route-table scale for "all but domestic". The fallbacks are safe but visible.
4. Fast Startup's "shut down" may not be a boot. Connect-on-boot's wording depends on a device check.
5. SmartScreen and Defender friction for non-technical members. That is TP-051's to decide, but it shapes M5's done-when.

## Appendix: sources

Checked 2026-11-15.

1. Wintun: <https://git.zx2c4.com/wintun/about/>
2. Wintun README, `api/adapter.h` (close removes a created adapter; orphan cleanup): <https://git.zx2c4.com/wintun/tree/README.md>, <https://git.zx2c4.com/wintun/tree/api/adapter.h>
3. `winipcfg` (`SetRoutes` flushes first): <https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/luid.go>; Tailscale's use: <https://github.com/tailscale/tailscale/blob/main/wgengine/router/ifconfig_windows.go>
4. wireguard-windows default-route monitor: <https://git.zx2c4.com/wireguard-windows/tree/tunnel/defaultroutemonitor.go>
5. OpenVPN forum, "Extremely long routing tables": <https://forums.openvpn.net/viewtopic.php?p=103139>
6. Persisted routes: <https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmiiprouteprov/win32-ip4persistedroutetable>; `MIB_IPFORWARD_ROW2`: <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2>
7. OpenVPN `block_dns.c`: <https://third-party-mirror.googlesource.com/openvpn/+/refs/heads/master/src/openvpn/block_dns.c>
8. wireguard-windows firewall (`blocker.go`, `rules.go`): <https://github.com/WireGuard/wireguard-windows/tree/master/tunnel/firewall>; kill-switch note: <https://git.zx2c4.com/wireguard-windows/tree/docs/netquirk.md>
9. Smart multi-homed name resolution and its policy's limits: <https://www.ghacks.net/?p=136550>, <https://www.ovpn.com/en/blog/deactivate-smart-multi-homed-name-resolution-in-windows-8-8-1-and-10>
10. Tailscale DNS on Windows (NRPT, GP precedence, `Resolve-DnsName`): <https://tailscale.com/docs/reference/dns-in-tailscale.md>, <https://github.com/tailscale/tailscale/blob/main/net/dns/nrpt_windows.go>
11. Microsoft, NRPT: <https://learn.microsoft.com/en-us/windows-server/networking/dns/name-resolution-policy-table>
12. Windows DoH: <https://techcommunity.microsoft.com/blog/networkingblog/windows-insiders-gain-new-dns-over-https-controls/2494644>
13. Microsoft, `pktmon`: <https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon>
14. Microsoft, IPv6 and transition technologies (`DisabledComponents`): <https://support.microsoft.com/en-us/help/929852>
15. Mullvad security doc (persistent blocking sublayer): <https://github.com/mullvad/mullvadvpn-app/blob/main/docs/security.md>
16. Microsoft, WFP filter arbitration: <https://learn.microsoft.com/windows/win32/fwp/filter-arbitration>
17. Microsoft, WFP object management; `FWPM_SESSION0`: <https://learn.microsoft.com/windows/win32/fwp/object-management>, <https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0>
18. Microsoft, WFP operation (boot-time filters); `FWPM_FILTER0`; Quarkslab on persistent state: <https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation>, <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0>, <https://blog.quarkslab.com/windows-filtering-platform-persistent-state-under-the-hood.html>
19. Mullvad, "Linux under WSL2 can be leaking": <https://mullvad.net/en/blog/linux-under-wsl2-can-be-leaking>
20. `SERVICE_FAILURE_ACTIONS_FLAG`; `svc/mgr`: <https://learn.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-service_failure_actions_flag>, <https://pkg.go.dev/golang.org/x/sys/windows/svc/mgr>
21. Fast Startup hibernates the kernel session; power states: <https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/fast-startup-causes-system-hibernation-shutdown-fail>, <https://learn.microsoft.com/en-us/windows/win32/Power/system-power-states>
22. go-winio pipes: <https://pkg.go.dev/github.com/Microsoft/go-winio>
23. Tailscale `safesocket` (Identification-level dial): <https://github.com/tailscale/tailscale/blob/main/safesocket/pipe_windows.go>
24. Wintun builds and prebuilt-binaries licence: <https://www.wintun.net/>, <https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt?h=0.10.2>
25. Go FAQ on virus scanners; a report; SignPath Foundation: <https://go.dev/doc/faq#virus>, <https://groups.google.com/g/golang-nuts/c/Au1FbtTZzbk>, <https://signpath.org/>
26. SmartScreen reputation; code-signing options: <https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation>, <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options>
27. Go 1.17 ports: <https://go.dev/doc/go1.17#ports>
28. WireGuard for Windows 0.3 (ARM64): <https://lists.zx2c4.com/pipermail/wireguard/2020-November/006075.html>
29. `wf` (BSD-3); Tailscale on the Windows firewall: <https://pkg.go.dev/inet.af/wf>, <https://tailscale.com/blog/windows-firewall>
