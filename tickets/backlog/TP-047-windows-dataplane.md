---
id: TP-047
title: "Windows data plane"
milestone: M5
area: dataplane
stream: core
repo: thinkpol-vpn
size: epic
depends_on: [TP-019, TP-021, TP-046, TP-075, TP-102]
refs: [D1]
needs_human: windows
owner: ""
branch: ""
---

## Goal
The device data plane runs on Windows.

## Scope (split before starting)
- Windows service install and connect-on-boot (moved from TP-046; macOS and Linux stay in TP-046).
- Wintun via `wireguard-go/tun`.
- netcfg adapter (e.g. `winipcfg` from wireguard-windows).
- Route-table enforcement: big route tables are slow on Windows; measure, consider a WFP-based alternative.
- DNS through NRPT; IPv6 leak prevention.
- Local API over a named pipe (check KRN-001 covers it).

## Notes

Moved here from [docs/design/windows.md](../../docs/design/windows.md) in its review round 2 (2026-11-15): the proposed split, the device sessions, A0's checklist and plan B, the owner questions, and both review rounds. Proposed, not filed: the tickets are filed, and this split leaves here, when the owner answers the questions. Round 1 called the proposed residual rows RR66–RR76; since round 2 they are RR80–RR90 (M3's design proposes rows from RR66), and the final numbers are set when the tickets are filed.

### Proposed split

TP-047's scope list becomes ten tickets and a follow-up. Plan for 1.5–2x the sizes (past estimates ran about 2x optimistic).

| Id | Title | Size | Deps | Files |
|---|---|---|---|---|
| TP-W1 | Windows build, harness, A0 probe; `BootSession`, `trusteddir` | M | — | `Makefile` (`build-windows`, `windows/arm64` lint), `tun/wintun_embed_windows.go`, `tun/wintun_stub_windows.go`, `trusteddir/trusteddir_windows.go`, `trusteddir/boot_windows.go`, `internal/windowsdevice/` (harness, probe), a runbook page |
| TP-W2a | WFP engine adapter: two sessions, the adapter lock, engine errors and the forced re-apply, going down by closing the dynamic session, the `Dnscache` process check; library spike | M | W1 | `firewall/wfp_windows.go`, `firewall/engine.go` (fake), `firewall/dnscache_windows.go`, `go.mod` |
| TP-W2b | Kill switch on WFP; keeps TP-076's id; closes on its fakes and A0 | M | W2a | `firewall/killswitch_windows.go`, `firewall/inspect_windows.go`, `firewall/testdata/`, `agent/killswitch.go` (`linksMarked`) |
| TP-W3a | Wintun and netcfg | M | W1 | `tun/tun_windows.go`, `netcfg/netcfg_windows.go`, `netcfg/watch_windows.go`, `netcfg/inspect_windows.go` |
| TP-W3b | Route table: no rejects, diffs, record, `IP_UNICAST_IF`, timings | M | W3a | `routetable/split.go`, `routetable/control_windows.go`, `netcfg/record_windows.go`, shared golden layouts |
| TP-W2c | Guard on WFP, with the DNS block and the `Dnscache` block | M | W2a, W3b | `firewall/guard_windows.go`, `firewall/testdata/`, `cmd/thinkpol/platform_guard_host.go` |
| TP-W4 | DNS on Windows | M | W2c, W3a | `dns/system_windows.go`, `dns/inspect_windows.go`, `dns/watch_windows.go` |
| TP-W6 | Local API over a named pipe; the `Principal` seam; a failed Listen retried, `local_api_unavailable` | M | W1 | `localapi/auth.go`, `localapi/listen_windows.go`, `localapi/peercred_windows.go`, `localapi/client.go`, `localapi/group_windows.go` |
| TP-W5 | Agent platform: state, lock, record, crash trace, rollback; cross-OS: rollback `-kill-switch-off` and `-wait`, `KillSwitchStopNote` per OS | M | W2b, W2c, W3b, W4, W6 | `agent/hostlock_windows.go`, `agent/connectrecord_windows.go`, `agent/crashtrace_windows.go`, `agent/statedir_windows.go`, `agent/supported_windows.go`, `agent/platform.go`; cross-OS: `cmd/thinkpol/rollback.go`, `agent/rollback.go`, `agent/devicefile.go`, `agent/killswitch.go`, their tests, `docs/design/security.md` (rollback) |
| TP-W7 | Windows service: install (the "restore network" shortcut, the intended-stop marker), uninstall, non-zero stops and recovery, connect-on-boot; TP-076's acceptance | M | W5 | `service/sc_windows.go`, `service/host_windows.go`, `service/install.go`, `service/shortcut_windows.go`; RR80–RR90 into RESIDUAL-RISKS.md |
| TP-W8 | Windows diag (online) and device checklist | S | W7, TP-133 | `agent/diagnose_windows.go`, readers in their packages |
| follow-up | Windows offline diag readers (TP-133's kind: elevated; unelevated is 77) | S | W8, TP-133 | `agent/diagnose_windows.go`, `cmd/thinkpol/diag.go` |

- **TP-076.** W2b keeps TP-076's id and scope and closes on its fakes (goldens; the change order and going down on the fake engine) plus A0's WFP checks. TP-076's three acceptance boxes move to W7 and run at session C, so no ticket waits on a later one.
- **TP-133** moved to M2 on 2026-11-15 and is merging, so W8 may depend on it; W8 needs only online diag. The follow-up is proposed, not filed.
- **Cross-OS cost of W5:** rollback's two options and the stop note change Linux and macOS behaviour too, with the files listed; their tests run in the lab, macOS's on the development machine.
- **W2a's spike checklist** (library or our own thin binding): transactions; `FwpmFilterSubscribeChanges0` filtered by provider; non-dynamic and dynamic sessions side by side; closing a dynamic session; add and delete by key; `ALE_USER_ID` security-descriptor conditions, a service SID among them; `IPFORWARD` layers; enumeration by provider; the three engine errors told apart from the rest. Pin a commit.

### Device sessions

- **A0**, at the end of W1: the throwaway probe, before any golden filter is written;
- **A1**, after W3b: routes, timings, socket binding, the LUID, the adapter's fate after a kill;
- **B**, after W5: the data plane run by hand under a SYSTEM scheduled task;
- **C**, after W7: the service, TP-076's acceptance, the restart after `net stop bfe`, both recoveries (one step and by hand), connect-on-boot across a full restart.

Pre-service sessions run the agent as a SYSTEM scheduled task (`schtasks /ru SYSTEM`) from the installed path, so the agent permit matches; the harness takes the app ID and SID to permit as parameters, so the probe can permit itself. A0 has no TUN: "connected" there is a TCP flow passing under a dynamic permit for its destination on the uplink, with a static block-all beneath.

### A0 checklist

WFP:
- an unsigned elevated binary runs at all (Smart App Control, if on, has no "Run anyway": [source 39](../../docs/design/windows.md#appendix-sources));
- static objects survive `taskkill /F` and dynamic ones don't;
- closing a dynamic session deletes its objects at once;
- a dynamic filter works inside a static sublayer;
- a key re-added in the transaction that deleted it;
- two transactions on one session (`FWP_E_TXN_IN_PROGRESS`, or joined);
- a static replace by key during a "connected" flow drops nothing (and whether flows are re-authorised);
- the kill switch's Close leaves the guard whole;
- 10k-condition filters and the chunked fallback.

BFE and SCM:
- `net stop bfe` with a throwaway `sc.exe` service depending on BFE: BFE's state when the dependent gets its stop (expected RUNNING), what's removed, whether recovery restarts the dependent and starts BFE, how long BFE's RPC lags its RUNNING;
- Fast Startup: which of the service, the static objects, the volatile key, the adapter and the routes survive "Shut down".

Pipe: a member's `CreateNamedPipe` on the name fails, a non-admin can't create under the prefix, and the owner check works.

DNS:
- the DNS block under `pktmon`; the `Dnscache` block with DoH set on the uplink, on 443 and on another port;
- `tasklist /svc /fi "services eq dnscache"`: `Dnscache` alone in its process; the process token holds `NT SERVICE\Dnscache` (and which other service SIDs).

May stay unproven on this device, and their rows say so:
- ND at ALE (needs native IPv6; RR84);
- WSL2 (NAT and mirrored), Docker and Hyper-V, if not installed (RR82): `curl -4`, `curl -6`, `dig` at the uplink's resolver, with the down shape and with the guard.

Nothing to probe: the preshutdown timeout (`sc.exe` sets it; nothing depends on its value).

### Plan B: if A0 says no

| Check | If no |
|---|---|
| static survives `taskkill /F`, dynamic doesn't | the crash posture can't rest on sessions: stop and redesign with persistent filters (question 10) |
| dynamic filter in a static sublayer | everything static, narrowed by the start-time cleanup as on macOS (direct stays until the restart, RR18); going down deletes by key and exits non-zero on a failure |
| closing a dynamic session deletes its objects | going down deletes by key; a failure exits non-zero (BFE ends a dead process's session) |
| re-adding a key in the deleting transaction | static filters alternate slots too |
| a static replace keeps flows | static filters alternate slots, so a flow is never unmatched |
| BFE RUNNING when a dependent gets its stop | nothing: every non-intended stop exits non-zero anyway |
| SCM restarts the dependent after `net stop bfe` | the tray starts the service (question 15); without the tray, until a reboot (RR81) |
| Fast Startup keeps the static objects | yes: "Shut down" is no way out (runbook); no: it is, and the wording says so |
| the protected prefix refuses non-admins | the non-fatal Listen and the owner-SID check carry it; a squatting row comes back |
| the service SID matches `Dnscache` alone | no `Dnscache` block anywhere; `Problem` reports it (RR89) |
| 10k conditions in one filter | chunked filters |
| an unsigned binary runs | question 13 b or c before anything else |
| kernel ND meets ALE | the ND permit (weight 7) is harmless; RR84 narrows |
| WSL2 or Docker leaks | RR82 says "leaks" instead of "unproven"; a follow-up for the F layers |

### Owner questions

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
10. **Boot window.** a) static objects, gone at a full restart (RR66); b) persistent down-shape filters while the toggle is on. *Rec: a* for M5 (RR80), with A0's Fast Startup result in its wording; take b up with RR59 as one cross-OS ticket.
11. **WFP library.** a) `github.com/tailscale/wf` at a pinned commit; b) wireguard-windows' syscall layer plus the few calls it lacks; c) our own thin binding on `x/sys/windows`. *Rec: a* only if W2a's spike passes the whole checklist, else b (Fable expects b).
12. **`wintun.dll`.** a) fetched by pinned hash, embedded behind the build tag, verified and rewritten at start; b) committed; c) the user downloads it; d) shipped beside the binary by TP-051's package. *Rec: a,* d if TP-051's package makes it free.
13. **Signing for M5.** a) unsigned, with SmartScreen steps in the runbook; b) an OV certificate now; c) apply to SignPath now. *Rec: a* if question 4 is a, and c now for its lead time; details are TP-051's.
14. **If 10k direct routes are slow.** a) accept: tunnelled meanwhile; b) cap and tunnel the smallest prefixes, said in health; c) no "all but domestic" on Windows. *Rec:* decide after A1 (which times filter conditions too); default a, then b.
15. **The tray and a stopped service.** a) the group gets start, query-status and interrogate: the tray starts a service it should see running, and infers a restart loop from SCM's status (process-ID changes); b) query only (the loop is still inferred). *Rec: a.* Starting only restores protection, and it is the BFE-stop fallback.
16. **The DNS divergence.** a) accept: no LAN or direct-set resolver while connected on Windows (RR88), stated in security.md; b) a later ticket: allow-LAN may name LAN resolvers to permit, refused when one is also an uplink's resolver; c) match the other OSes (lets lookups reach the router: rejected). *Rec: a* for M5, b if a member asks.

### Review round 1

Reviews of the note at `394e750` (2026-11-15): go-paranoid (P), Fable 5.2 (F, in its order), pocket-torvalds (T). How each was handled; RR numbers as they were then.

| # | Finding | Handling |
|---|---|---|
| P1 | Shared provider: Close deletes the other owner's filters; watches ping-pong | **Changed design**: a provider per owner, stable keys, changes by key; watches per provider ([firewall](../../docs/design/windows.md#firewall-two-owners-two-sessions)) |
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

### Review round 2

go-paranoid's review of the note at `7cd5106` (2026-11-15), with the orchestrator's decisions. How each was handled.

| # | Finding | Handling |
|---|---|---|
| 1 | Going down deletes TUN and `Direct` by key; a failed delete leaves the old `Direct` open to every process | **Changed design**: going down closes the dynamic session (BFE deletes it whole); a failed close exits non-zero; in-between states proved with leaks and blocks apart; A0 checks both deletions |
| 2 | Both owners share the session handles: transactions join or collide; a watch re-apply between steps 1 and 3 | **Changed design**: one adapter lock over every transaction, re-apply and reopen; steps 1–3 under it; A0 checks two transactions on one session |
| 3 | "Any engine error" drops both sessions (a neighbour's `FWP_E_TIMEOUT` too); the keeper's skip leaves 5 s unenforced after a reopen | **Changed design**: engine error is exactly a dead handle, `RPC_S_SERVER_UNAVAILABLE`, `FWP_E_SESSION_ABORTED`; the adapter re-applies each owner's last set itself after a reopen |
| 4 | `net stop bfe` stops thinkpol first while BFE runs, so it exits 0 and stays stopped | **Changed design**: every non-shutdown stop exits non-zero unless install, uninstall or update marked it intended; the first engine open backs off; A0's throwaway service, C's restart |
| 5 | Recovery fails as written: PowerShell's `sc`, thinkpol not on PATH, taskkill backwards, `restart_loop` never served; needs an elevated terminal | **Fixed**: `sc.exe`, the full path, taskkill wording; the tray infers a loop from SCM process IDs; rollback `-kill-switch-off` and `-wait` in W5 (cross-OS, files listed); a "restore network" shortcut from install (W7) as the one step |
| 6 | Ticket cycle: TP-076's acceptance only at C | **Fixed**: W2b closes on fakes and A0; TP-076's acceptance in W7 |
| 7 | W8 depends on TP-133 | **Kept**: TP-133 is in M2 since 2026-11-15; W8 is online only; offline readers are a proposed follow-up |
| 8 | Size 48.7 KB | **Fixed**: split, sessions, A0, questions and both rounds moved here; the note is 40.5 KB (round 2's design additions cost about 4 KB) |
| 9 | DNS divergence understated; RR76 and `KillSwitchStopNote` need Windows wording | **Fixed**: security.md and RR88 name direct-set resolvers and the toggle-off stop; RR90 reworded; the stop note's Windows wording set, changed in W5 |
| S1 | `Dnscache` confined only on 443; no kill-switch W12, so DoH to a LAN resolver passes the down shape with allow-LAN | **Changed design**: `Dnscache` blocked on every port off the TUN but 5353 and 5355, by both owners |
| S2 | Shared svchost below 3.5 GB: a service SID matches the whole process | **Changed design**: each apply checks `Dnscache` runs alone, else no block and `Problem` (RR89); A0 runs `tasklist /svc` and a token check |
| S3 | A squatted pipe plus a fatal Listen is a restart loop | **Changed design**: a failed Listen retries with backoff, the data plane runs, health says `local_api_unavailable` |
| A0 | Missing checks; "connected" without a TUN; unprovable checks; no plan B | **Fixed**: four checks added (key re-add, BFE state at a dependent's stop, two transactions, `Dnscache` sharing) plus the dynamic close; "connected" defined; ND and WSL2 may stay unproven; plan-B table; the adapter's fate moved to A1 |
| RR | M3's design also proposes rows from RR66 | **Fixed**: Windows' rows renumbered RR80–RR90 |

## Log
- 2026-10-10 created in backlog
- 2026-10-15 docs (backlog grooming): depends on TP-075; Windows service scope from TP-046
- 2026-10-15 docs (backlog grooming, review fixes): depends_on TP-046; removed redundant split note
