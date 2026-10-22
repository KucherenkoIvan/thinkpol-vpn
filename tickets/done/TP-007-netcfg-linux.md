---
id: TP-007
title: "Network config port and Linux adapter"
milestone: M0
area: dataplane/netcfg
repo: thinkpol-vpn
size: M
depends_on: [TP-001]
refs: [N1, docs/design/security.md#ipv6]
owner: "agent-tp-007"
branch: "tp-007-netcfg-linux"
---

## Goal
One port for OS-level network setup (addresses, MTU, link state, routes), with a Linux adapter on netlink instead of shelling out.

## Scope
- Port: set IPv4 + IPv6 (ULA) addresses on an interface, MTU, up/down, add/remove routes (prefix via interface or gateway, routing table), default gateway per address family.
- Linux adapter on netlink (pure Go, e.g. `vishvananda/netlink`).
- Cleanup is part of the contract: the adapter records what it added and removes it on close, also after a partial failure.
- Tests run inside a network namespace (root needed; run in a lab container or skip).

## Out of scope
macOS (TP-019), Windows (TP-047), rule-driven route tables (TP-018).

## Acceptance
- [x] addresses, MTU and routes applied and fully removed in the namespace test — `TestApplyThenCloseRestoresEverything`: dual-stack addresses, MTU, link up, on-link, gateway, default and metric routes; re-Apply makes zero netlink address/route events; after Close the namespace's links, addresses and routes in every table equal the snapshot from before, and the lab node's own namespace is unchanged. `TestApplyConverges`, `TestReApplyRepairsOutsideChanges`, `TestCloseAfterTheInterfaceIsGone`, `TestForeignStateIsNeverTouched`, `TestMTUChangedSinceIsKept`, `TestOwnersNeverTouchEachOther`, `TestOneConfiguratorPerOwnerAndNamespace` cover updates, outside changes, vanished interfaces and foreign state.
- [x] a failure halfway through leaves nothing behind — `TestFailedFirstApplyLeavesNothing` (the kernel rejects the last route after addresses, MTU, link and earlier routes were applied, proven by the netlink events seen; also a missing interface) and `TestCancelledApplyLeavesNothing` (ctx ends after the interface and four routes) end equal to the before-snapshot; `TestFailedUpdateKeepsThePreviousConfig` ends equal to the previously applied state; `TestTakesOverRoutesLeftByACrash` ends equal to the crash leftovers.

Evidence: `make lint` and `make test` green; `make lab-gotest PKG=./internal/dataplane/netcfg/...` green 3 runs in a row (18 tests; each works in its own `ip netns add` namespace, deleted in cleanup, and only reads the node's own namespace). Takeover of 4000 routes left by a crashed process: ~10–15 ms with zero netlink changes; Close of them ~85–105 ms.

## Notes
**Port contract** (`internal/dataplane/netcfg`, `netcfg.go`):
```go
type Owner int // OwnerOverlay (TP-008), OwnerSupervisor (TP-009), OwnerRouteTable (TP-018); netcfg.Owners lists them
type Config struct { Interfaces []Interface; Routes []Route }
type Interface struct { Name string; Addrs []netip.Prefix; MTU int; Up bool } // MTU 0 / Up false: leave alone
type Route struct { Dst netip.Prefix; Gateway netip.Addr; Interface string; Metric int } // main table only, Metric ≤ MaxUint32
type Configurator interface {
	Apply(ctx context.Context, cfg Config) error              // converge to cfg against the kernel, all or nothing
	DefaultRoute(ctx context.Context, f Family) (Route, error) // usable physical default route, no owner's
	Close() error                                              // remove all owned, restore links; retryable
}
func New(owner Owner) (Configurator, error)                       // every OS; ErrUnsupported where no adapter yet
func NewInNamespace(path string, owner Owner) (Configurator, error) // linux && !android only
func (Owner) RouteProtocol() netlink.RouteProtocol                 // linux: 84 overlay, 85 supervisor, 86 route-table
const LockDir = "/run/thinkpol/netcfg"                             // linux: per-(namespace, owner) lock files
var ErrConflict, ErrNoDefaultRoute, ErrClosed, ErrBusy error
```
- **Owners.** Every configurator works for one owner; owners have their own route protocol and never touch each other's routes (another owner's or a foreign route at the same identity → `ErrConflict`). At most one configurator per owner is alive in a network namespace: it holds an exclusive flock on `LockDir/<nsfs dev>-<inode>.<owner>.lock` (O_CLOEXEC, so exec'd children don't inherit it; released by the kernel when the process dies); a second fails at construction with `ErrBusy`. The lock files are empty and left in place (tmpfs; unlinking lock files races).
- **Declarative, against the kernel.** Apply takes the whole desired state. It dumps the main table's routes with the owner's protocol (both families) and every address once, and decides from that dump: every route with our protocol is ours (the lock guarantees it), so those the config wants are kept or replaced, and all others are deleted, a dead predecessor's leftovers included (on the first Apply that is the takeover). Owned state removed from outside or gone with a recreated interface is added back. Re-applying is a no-op (no netlink events), and a reconcile is O(routes). Every step pushes its inverse to an undo log; a failing or cancelled Apply runs it, so the system is as before the call (leftovers included). `Config.Validate` rejects bad input before anything changes (masked Dst, families match, no zoned gateways, link-local IPv6 gateways need an interface, metric within 32 bits, IPv6 MTU ≥ 1280); the Linux adapter also rejects two routes with the same kernel identity (IPv6 metric 0 is 1024). `block` is the firewall's job, not a route type.
- **Ownership details.** Deletes use the kernel's exact entry (scope, metric, nexthop, protocol), so nothing else can match. An address present with another prefix length → `ErrConflict`. Addresses already present are used but not owned (they can't be tagged; a crashed TUN takes its addresses along anyway). MTU and link-up changes are restored when the interface leaves the config or on Close, each only if still what we set. Interfaces are never created or deleted here. Removing an owned primary IPv4 address takes the subnet's secondaries with it unless `promote_secondaries` is set (documented on `Interface.Addrs`).
- **Libraries.** `vishvananda/netlink` + `vishvananda/netns`: pure Go, the de facto netlink library (Docker/moby, Kubernetes CNI plugins, Cilium, Flannel); addresses, links, routes, subscriptions and per-namespace handles (`NewHandleAt`), so nothing shells out and no thread has to enter the namespace. Considered `jsimonetti/rtnetlink` (pure Go too, lower level, more code here for the same thing). No nftables in this ticket: the port's scope is addresses/MTU/links/routes; nftables belongs to `egress` (TP-014) and `firewall` (TP-021, TP-048).
- **Android.** The adapter is `linux && !android`; Android gets the `ErrUnsupported` stub (VpnService sets addresses and routes there), so netlink never enters the Android build. `make lint` builds netcfg for android/arm64.
- **Gotcha found:** vishvananda/netlink sends the route's own scope on RTM_DELROUTE (zero = universe), not "any", so deleting an IPv4 on-link route needs scope link; hence deletes from the dump's exact entry.

**For downstream tickets:**
- **TP-008** (TUN): `New(OwnerOverlay)` (or `NewInNamespace(..., OwnerOverlay)` from outside a worker); create the TUN with `wireguard-go/tun`, then `Apply` an `Interface{Name, Addrs: [v4/10, ULA/48], MTU, Up: true}` plus overlay routes; Close before or after closing the TUN (a gone interface counts as cleaned). If the TUN is recreated, re-Apply puts everything back. A restart after a crash cleans up the predecessor's overlay routes on its first Apply.
- **TP-009** (supervisor): creating netns and veths is yours (netlink + netns, same libraries). Use `OwnerSupervisor` for the veth ends: `New(OwnerSupervisor)` in the root namespace and `NewInNamespace("/run/netns/<space>", OwnerSupervisor)` for the space end, while the worker inside uses `OwnerOverlay`: different owners coexist in one namespace. One configurator per owner and namespace (`ErrBusy` otherwise). Tests: copy `newTestNS` from `netcfg_linux_test.go` (fresh `ip netns add` per test, deleted in cleanup) and the re-exec crash helper in its `TestMain`.
- **TP-018** (route table): `New(OwnerRouteTable)`. `DefaultRoute(IPv4/IPv6)` gives the physical gateway (dead/linkdown routes and every owner's routes skipped); put `direct` prefixes and entry endpoints (/32, /128) via it, split defaults `0.0.0.0/1`+`128.0.0.0/1` and `::/1`+`8000::/1` via the TUN (a plain default would hit the foreign default → `ErrConflict`). On gateway change, `Apply` the new full config: only the changed routes are touched, but a changed route is delete-then-add, so it falls back to the next route for a moment. A `WatchDefaultRoute` in the port is welcome when TP-018 needs it (not built now; netlink route events, ignoring every `Owner.RouteProtocol()`). The port has no routing tables or rules: per-space namespaces each have their own main table; if TP-018 needs policy routing it adds rules + tables (noted in TP-018).
- **TP-019** (macOS): implement `New(owner)` in `netcfg_darwin.go` with the same contract; `Metric != 0` → `ErrUnsupported` (no route metrics there). Per-owner identity: tag routes with a route flag (`RTF_PROTO1`/`RTF_PROTO2`/`RTF_PROTO3`, one per owner) or, failing that, keep an owner's routes in a state file; liveness: an exclusive flock on a lock file per owner (one network namespace on macOS). `ifconfig`/`route` exec only as a documented fallback. Reuse the Linux tests' scenarios as the manual checklist.
- **TP-021 / TP-048** (leaks, kill switch) and **TP-014** (egress): nftables lives in `firewall`/`egress`, not here; own a dedicated table (e.g. `inet thinkpol`) and delete exactly that table, the same ownership rule as the route protocols.
- **TP-047** (Windows): `winipcfg` (LUID `AddIPAddress`/`AddRoute`/`SetMTU`); tag routes per owner via `MIB_IPFORWARD_ROW2.Protocol` if feasible, else in-memory ownership only; a lock file per owner for liveness.

## Review findings
- [x] 1 (blocker) Apply diffs against one kernel dump (proto-84 routes per family, all addresses) keyed by the normalized key; owned-but-missing is re-added; takeover/conflict use the same map. Tests: `TestReApplyRepairsOutsideChanges` (outside route deletes v4/v6, address removals v4/v6, MTU change, interface deleted and recreated with gateway-only routes coming back), `TestReApplyAfterACrashIsLinear` (4000 routes: takeover ~15 ms, zero changes, bound 3 s).
- [x] 2 Takeover only until a configurator's first successful Apply, and only if no other configurator is alive in the namespace (shared flock on the namespace file, exclusive probe at construction); otherwise `ErrConflict`. Documented in the `Configurator` contract. Tests: `TestTwoConfiguratorsInOneNamespace`, `TestTakesOverRoutesLeftByACrash` (real crash: a re-exec'd child exits without Close).
- [x] 3 No per-route dumps any more (see 1).
- [x] 4 Duplicate kernel keys rejected before any change: `TestSameRouteTwiceIsRejectedBeforeAnyChange` (zero netlink events).
- [x] 5 MTU/up restored only if still ours: `TestMTUChangedSinceIsKept`.
- [x] 6 Same IP, other prefix → `ErrConflict` for both families, checked against the dump before adding: `TestForeignStateIsNeverTouched`.
- [x] 7 `Route.Table` removed; TP-018's Notes say it adds rules + tables if needed; `Route` doc says blocking is the firewall's job.
- [x] 8 Validate rejects zoned gateways and interface-less link-local IPv6 gateways (`TestValidate`); Apply after Close returns `ErrClosed` before validating (`TestApplyThenCloseRestoresEverything`).
- [x] 9 Deletes use the dump's exact entry (`exactRoute`), and only routes present in the dump are deleted.
- [x] 10 DefaultRoute skips `RTNH_F_DEAD`/`RTNH_F_LINKDOWN` routes and nexthops, errors without gateway and interface: `TestDefaultRoute` (a better default route on a veth without carrier is ignored, both families).
- [x] 11 Undo of a takeover re-adds the leftover (`TestTakesOverRoutesLeftByACrash`); deleting an already-gone route pushes no re-add; undo of an add, an MTU or a link change restores the record only after the kernel revert succeeded. IPv4 primary-address side effect documented on `Interface.Addrs`.
- [x] 12 Notes updated for TP-019 (metrics) and TP-018 (WatchDefaultRoute later, delete-then-add).
- [x] Tests for the gaps: interface recreate, outside removal, IPv6 takeover (gateway change over a leftover), ctx cancellation midway (`TestCancelledApplyLeavesNothing`), third-party MTU change, IPv4/IPv6 different prefix, normalized duplicate keys, two configurators in one namespace.

### Round 3 (delta review)
- [x] R3.1 Per-owner identity: the constructor takes an owner role (documented enum), each with its own route protocol number; liveness is an exclusive flock per (namespace inode, owner) held for the configurator's life (O_CLOEXEC); a second configurator of the same owner in the same namespace fails at construction with ErrBusy; different owners never adopt each other's routes (another owner's or a foreign route at the same key → ErrConflict). Replaces the namespace-wide `alone` heuristic, which let a configurator created before another take the other's routes.
- [x] R3.2 Takeover: every route with our protocol is ours (the lock guarantees leftovers are a dead predecessor's): adopt those the config wants, delete those it doesn't (undo re-adds them if the Apply fails); leftovers outside the new config no longer linger and cause ErrConflict later.
- [x] R3.3 Validate rejects Metric > math.MaxUint32.
- [x] R3.4 Tests: reversed-order creation (different owners → ErrConflict, same owner → ErrBusy), crash config differs from the new config, two owners crash/restart independently, metric bound. Port doc and Notes for TP-008/009/018/019 updated.
- Round 3 resolution: `Owner` enum + `ErrBusy`, per-(namespace, owner) exclusive flock under `LockDir`, protocols 84/85/86; every route with our protocol is reconciled on every Apply (adopted, replaced or deleted), so the `takeover`/`alone` state and route records are gone. Tests: `TestOneConfiguratorPerOwnerAndNamespace`, `TestOwnersNeverTouchEachOther` (created first, applies last), `TestOwnersCrashAndRestartIndependently`, `TestTakesOverRoutesLeftByACrash` (new config drops a route and moves one; failed first Apply restores leftovers), `TestValidate` (metric > MaxUint32). DESIGN mentions netcfg only in the layout, no ownership: unchanged.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-007, branch: tp-007-netcfg-linux
- 2026-10-10 in-progress → review — make lint, make test, make lab-gotest (netcfg) green
- 2026-10-10 review → has-errors — review findings 1–12
- 2026-10-10 has-errors → in-progress — owner: agent-tp-007, fixing review findings
- 2026-10-10 in-progress → review — findings 1–12 fixed; make lint, make test green; lab-gotest (netcfg) green 3 runs in a row
- 2026-10-10 review → has-errors — delta review (round 3): takeover defects, metric overflow, per-owner liveness
- 2026-10-10 has-errors → in-progress — owner: agent-tp-007, fixing round 3
- 2026-10-10 in-progress → review — round 3 fixed; make lint, make test green; lab-gotest (netcfg) green 3 runs in a row
- 2026-10-10 review → done — merged into rewrite
