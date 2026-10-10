---
id: TP-007
title: "Network config port and Linux adapter"
milestone: M0
area: dataplane/netcfg
repo: thinkpol-vpn
size: M
depends_on: [TP-001]
refs: [N1, DESIGN#ipv6]
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
- [x] addresses, MTU and routes applied and fully removed in the namespace test — `TestApplyThenCloseRestoresEverything`: dual-stack addresses, MTU, link up, on-link, gateway, default and metric routes; re-Apply makes zero netlink address/route events; after Close the namespace's links, addresses and routes in every table equal the snapshot from before, and the lab node's own namespace is unchanged. `TestApplyConverges`, `TestReApplyRepairsOutsideChanges`, `TestCloseAfterTheInterfaceIsGone`, `TestForeignStateIsNeverTouched`, `TestMTUChangedSinceIsKept`, `TestTwoConfiguratorsInOneNamespace` cover updates, outside changes, vanished interfaces and foreign state.
- [x] a failure halfway through leaves nothing behind — `TestFailedFirstApplyLeavesNothing` (the kernel rejects the last route after addresses, MTU, link and earlier routes were applied, proven by the netlink events seen; also a missing interface) and `TestCancelledApplyLeavesNothing` (ctx ends after the interface and four routes) end equal to the before-snapshot; `TestFailedUpdateKeepsThePreviousConfig` ends equal to the previously applied state; `TestTakesOverRoutesLeftByACrash` ends equal to the crash leftovers.

Evidence: `make lint` and `make test` green; `make lab-gotest PKG=./internal/dataplane/netcfg/...` green 3 runs in a row (16 tests; each works in its own `ip netns add` namespace, deleted in cleanup, and only reads the node's own namespace). Takeover of 4000 routes left by a crashed process: ~15 ms with zero netlink changes; Close of them ~85 ms.

## Notes
**Port contract** (`internal/dataplane/netcfg`, `netcfg.go`):
```go
type Config struct { Interfaces []Interface; Routes []Route }
type Interface struct { Name string; Addrs []netip.Prefix; MTU int; Up bool } // MTU 0 / Up false: leave alone
type Route struct { Dst netip.Prefix; Gateway netip.Addr; Interface string; Metric int } // main table only
type Configurator interface {
	Apply(ctx context.Context, cfg Config) error              // converge to cfg against the kernel, all or nothing
	DefaultRoute(ctx context.Context, f Family) (Route, error) // usable physical default route, netcfg's excluded
	Close() error                                              // remove all owned, restore links; retryable
}
func New() (Configurator, error)                       // every OS; ErrUnsupported where no adapter yet
func NewInNamespace(path string) (Configurator, error) // linux && !android only
var ErrConflict, ErrNoDefaultRoute, ErrClosed error
const RouteProtocol = 84                               // linux: rtnetlink protocol on our routes
```
- **Declarative, against the kernel.** Apply takes the whole desired state. It dumps the main table's proto-84 routes (both families) and every address once, and decides everything from that dump and its own records: owned-but-missing state (removed from outside, or gone with a recreated interface) is added back, changed routes are replaced, routes and addresses no longer wanted are removed. Re-applying is a no-op (no netlink events), and a reconcile is O(routes). Every step pushes its inverse to an undo log; a failing or cancelled Apply runs it, so the system is as before the call. `Config.Validate` rejects bad input before anything changes (masked Dst, families match, no zoned gateways, link-local IPv6 gateways need an interface, IPv6 MTU ≥ 1280); the Linux adapter also rejects two routes with the same kernel identity (IPv6 metric 0 is 1024). `block` is the firewall's job, not a route type.
- **Ownership.** Routes carry protocol 84; deletes use the kernel's exact entry (scope, metric, nexthop, protocol), so nothing else can match. A route with the identity (Dst, metric) of someone else's fails with `ErrConflict`; so does an address present with another prefix length. Addresses already present are used but not owned (they can't be tagged; a crashed TUN takes its addresses along anyway). MTU and link-up changes are restored when the interface leaves the config or on Close, each only if still what we set. Interfaces are never created or deleted here. Removing an owned primary IPv4 address takes the subnet's secondaries with it unless `promote_secondaries` is set (documented on `Interface.Addrs`).
- **Crash takeover.** Each configurator holds a shared flock on the namespace file (nsfs inode, so every path to one namespace is one lock; released by the kernel when the process dies). If it could take the lock exclusively at construction, nobody else is alive there: its first Apply adopts identical proto-84 leftovers without touching them and replaces different ones; a failed first Apply puts the leftovers back. Otherwise, and after the first successful Apply, a proto-84 route it doesn't own is another live configurator's → `ErrConflict`. Two configurators in one namespace must not claim the same route.
- **Libraries.** `vishvananda/netlink` + `vishvananda/netns`: pure Go, the de facto netlink library (Docker/moby, Kubernetes CNI plugins, Cilium, Flannel); addresses, links, routes, subscriptions and per-namespace handles (`NewHandleAt`), so nothing shells out and no thread has to enter the namespace. Considered `jsimonetti/rtnetlink` (pure Go too, lower level, more code here for the same thing). No nftables in this ticket: the port's scope is addresses/MTU/links/routes; nftables belongs to `egress` (TP-014) and `firewall` (TP-021, TP-048).
- **Android.** The adapter is `linux && !android`; Android gets the `ErrUnsupported` stub (VpnService sets addresses and routes there), so netlink never enters the Android build. `make lint` builds netcfg for android/arm64.
- **Gotcha found:** vishvananda/netlink sends the route's own scope on RTM_DELROUTE (zero = universe), not "any", so deleting an IPv4 on-link route needs scope link; hence deletes from the dump's exact entry.

**For downstream tickets:**
- **TP-008** (TUN): create the TUN with `wireguard-go/tun`, then `Apply` an `Interface{Name, Addrs: [v4/10, ULA/48], MTU, Up: true}` plus overlay routes; Close before or after closing the TUN (a gone interface counts as cleaned). If the TUN is recreated, re-Apply puts everything back.
- **TP-009** (supervisor): creating netns and veths is yours (netlink + netns, same libraries). Configure the space end with `NewInNamespace("/run/netns/<space>")` (or `/proc/<pid>/ns/net`) and the root end with `New()`; one configurator per namespace, or disjoint routes. Tests: copy `newTestNS` from `netcfg_linux_test.go` (fresh `ip netns add` per test, deleted in cleanup) and the re-exec crash helper in its `TestMain`.
- **TP-018** (route table): `DefaultRoute(IPv4/IPv6)` gives the physical gateway (dead/linkdown routes skipped); put `direct` prefixes and entry endpoints (/32, /128) via it, split defaults `0.0.0.0/1`+`128.0.0.0/1` and `::/1`+`8000::/1` via the TUN (a plain default would hit the foreign default → `ErrConflict`). On gateway change, `Apply` the new full config: only the changed routes are touched, but a changed route is delete-then-add, so it falls back to the next route for a moment. A `WatchDefaultRoute` in the port is welcome when TP-018 needs it (not built now; netlink route events, ignoring `RouteProtocol`). The port has no routing tables or rules: per-space namespaces each have their own main table; if TP-018 needs policy routing it adds rules + tables (noted in TP-018).
- **TP-019** (macOS): implement `New()` in `netcfg_darwin.go` with the same contract; `Metric != 0` → `ErrUnsupported` (no route metrics there). Route sockets can tag ours with `RTF_PROTO1`/`RTF_PROTO2` to mirror protocol 84, and a lock file can stand in for the namespace flock; `ifconfig`/`route` exec only as a documented fallback. Reuse the Linux tests' scenarios as the manual checklist.
- **TP-021 / TP-048** (leaks, kill switch) and **TP-014** (egress): nftables lives in `firewall`/`egress`, not here; own a dedicated table (e.g. `inet thinkpol`) and delete exactly that table, the same ownership rule as protocol 84.
- **TP-047** (Windows): `winipcfg` (LUID `AddIPAddress`/`AddRoute`/`SetMTU`); tag routes via `MIB_IPFORWARD_ROW2.Protocol` if feasible, else in-memory ownership only.

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

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-007, branch: tp-007-netcfg-linux
- 2026-10-10 in-progress → review — make lint, make test, make lab-gotest (netcfg) green
- 2026-10-10 review → has-errors — review findings 1–12
- 2026-10-10 has-errors → in-progress — owner: agent-tp-007, fixing review findings
- 2026-10-10 in-progress → review — findings 1–12 fixed; make lint, make test green; lab-gotest (netcfg) green 3 runs in a row
