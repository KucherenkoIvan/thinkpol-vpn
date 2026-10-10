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
- [x] addresses, MTU and routes applied and fully removed in the namespace test — `TestApplyThenCloseRestoresEverything`: dual-stack addresses, MTU, link up, on-link/gateway/default routes in the main table and table 100; re-Apply makes zero netlink address/route events; after Close the namespace's links, addresses and routes in every table equal the snapshot from before, and the lab node's own namespace is unchanged. `TestApplyConverges`, `TestCloseAfterTheInterfaceIsGone`, `TestForeignStateIsNeverTouched` cover updates, vanished interfaces and foreign state.
- [x] a failure halfway through leaves nothing behind — `TestFailedFirstApplyLeavesNothing` (kernel rejects the last route after addresses, MTU, link and earlier routes were applied, proven by the netlink events seen; also a missing interface) ends equal to the before-snapshot; `TestFailedUpdateKeepsThePreviousConfig` ends equal to the previously applied state.

Evidence: `make lint` and `make test` green; `make lab-gotest PKG=./internal/dataplane/netcfg/...` green (3 runs in a row, all 9 tests pass; every test works in its own `ip netns add` namespace, deleted in cleanup, and only reads the node's own namespace).

## Notes
**Port contract** (`internal/dataplane/netcfg`, `netcfg.go`):
```go
type Config struct { Interfaces []Interface; Routes []Route }
type Interface struct { Name string; Addrs []netip.Prefix; MTU int; Up bool } // MTU 0 / Up false: leave alone
type Route struct { Dst netip.Prefix; Gateway netip.Addr; Interface string; Table, Metric int }
type Configurator interface {
	Apply(ctx context.Context, cfg Config) error            // converge, all or nothing
	DefaultRoute(ctx context.Context, f Family) (Route, error) // physical default route, ours excluded
	Close() error                                            // remove all owned, restore links; retryable
}
func New() (Configurator, error)                       // every OS; ErrUnsupported where no adapter yet
func NewInNamespace(path string) (Configurator, error) // linux && !android only
var ErrConflict, ErrNoDefaultRoute, ErrClosed error
const RouteProtocol = 84                               // linux: rtnetlink protocol on our routes
```
- **Declarative, not imperative.** Apply takes the whole desired state and diffs it against what this configurator owns: adds, changes (same identity, new gateway/interface) and removals in one call; re-applying is a no-op (no netlink events). Every step pushes its inverse to an undo log; a failing Apply runs it, so the system is as before the call. `Config.Validate` rejects bad input before anything changes (masked Dst, families match, IPv6 MTU ≥ 1280, no duplicate route identities).
- **Ownership.** Routes carry protocol 84 and every delete is sent with it, so the kernel itself refuses to delete a foreign route. A route add that hits an existing route with the same identity (table, Dst, metric) fails with `ErrConflict` unless that route is ours from a crashed run, which is taken over. Addresses already present are used but not owned (they can't be tagged; a crashed TUN takes its addresses along anyway). MTU and link-up changes are recorded and restored when the interface leaves the config or on Close. Interfaces are never created or deleted here.
- **Libraries.** `vishvananda/netlink` + `vishvananda/netns`: pure Go, the de facto netlink library (Docker/moby, Kubernetes CNI plugins, Cilium, Flannel), covers addresses, links, routes in any table, subscriptions and per-namespace handles (`NewHandleAt`), so nothing shells out and no thread has to enter the namespace. Considered `jsimonetti/rtnetlink` (pure Go too, but lower level, more code here for the same thing). No nftables in this ticket: the port's scope is addresses/MTU/links/routes; nftables belongs to `egress` (TP-014) and `firewall` (TP-021, TP-048).
- **Android.** The adapter is `linux && !android`; Android gets the `ErrUnsupported` stub (VpnService sets addresses and routes there), so netlink never enters the Android build. `make lint` builds netcfg for android/arm64.
- **Gotcha found:** vishvananda/netlink sends the route's own scope on RTM_DELROUTE (zero = universe), not "any", so deleting an IPv4 on-link route needs scope link. The adapter deletes with the route it added (or, for a takeover, the kernel's scope).

**For downstream tickets:**
- **TP-008** (TUN): create the TUN with `wireguard-go/tun`, then `Apply` an `Interface{Name, Addrs: [v4/10, ULA/48], MTU, Up: true}` plus overlay routes; Close before closing the TUN (or after: a gone interface counts as cleaned).
- **TP-009** (supervisor): creating netns and veths is yours (netlink + netns, same libraries). Configure the space end with `NewInNamespace("/run/netns/<space>")` (or `/proc/<pid>/ns/net`) and the root end with `New()`; one configurator per namespace. Tests: copy `newTestNS` from `netcfg_linux_test.go` (fresh `ip netns add` per test, deleted in cleanup).
- **TP-018** (route table): use `DefaultRoute(IPv4/IPv6)` for the physical gateway; put `direct` prefixes and entry endpoints (/32, /128) via it, split defaults `0.0.0.0/1`+`128.0.0.0/1` and `::/1`+`8000::/1` via the TUN (a plain default would hit the foreign default → `ErrConflict`). On gateway change, `Apply` the new full config: only the changed routes are touched. Thousands of routes are one netlink request each; measure before optimising. Watching changes: `netlink.RouteSubscribeWithOptions`, ignoring `Protocol == RouteProtocol`. A startup sweep of stale proto-84 routes is not here; add one if crashes leave routes not re-applied.
- **TP-019** (macOS): implement `New()` in `netcfg_darwin.go` with the same contract; `Table != 0` → `ErrUnsupported`. Route sockets can tag ours with `RTF_PROTO1`/`RTF_PROTO2` to mirror protocol 84; `ifconfig`/`route` exec only as a documented fallback. Reuse the Linux tests' scenarios as the manual checklist.
- **TP-021 / TP-048** (leaks, kill switch) and **TP-014** (egress): nftables lives in `firewall`/`egress`, not here; own a dedicated table (e.g. `inet thinkpol`) and delete exactly that table, the same ownership rule as protocol 84.
- **TP-047** (Windows): `winipcfg` (LUID `AddIPAddress`/`AddRoute`/`SetMTU`); tag routes via `MIB_IPFORWARD_ROW2.Protocol` if feasible, else in-memory ownership only.

## Review findings
- [ ] 1 (blocker) Apply diffs against the kernel, not memory: one dump of our proto-84 routes per family at the start of Apply, keyed by the normalized route key; owned-but-missing → add; takeover/conflict checks use the same map; addresses checked against `existing` before the owned shortcut. Tests: interface deleted and recreated under the same name (gateway-only routes come back), outside address removal flushing routes, outside route delete. The single dump also removes the O(n²) EEXIST dumps (#3): a test/benchmark with a few thousand routes shows re-Apply after a crash is O(n).
- [ ] 2 Takeover only on a configurator's first Apply (crash recovery); later, a proto-84 route with the same key that isn't ours → ErrConflict. Document: two configurators in one namespace must not claim the same route key; the second gets ErrConflict.
- [ ] 3 O(n²) dumps on EEXIST (fixed by 1).
- [ ] 4 Reject two routes with the same normalized key (IPv6 metric 0 ≡ 1024) before any change.
- [ ] 5 Restore MTU/up only if the current value still equals what we applied.
- [ ] 6 Same IP with a different prefix length → ErrConflict for both families; fix the comment.
- [ ] 7 Drop `Route.Table` (per-space namespaces have their own main table; macOS has none); TP-018 adds rules+tables if needed (TP-018 Notes). Port doc: `block` is the firewall's job, not routes.
- [ ] 8 Validate rejects zoned gateways and link-local IPv6 gateways without Interface; Apply on a closed configurator returns ErrClosed before validation.
- [ ] 9 Deletes target exactly our route, using the kernel dump's entry (incl. metric).
- [ ] 10 DefaultRoute skips linkdown/dead routes and errors when neither gateway nor interface is set (nexthop objects).
- [ ] 11 Undo exactness: undoing a takeover restores the leftover; undoing a delete of an already-gone route doesn't re-add; a failed MTU undo keeps its record. Document IPv4 primary-address deletion side effects (promote_secondaries).
- [ ] 12 Notes: TP-019 Metric != 0 unsupported on macOS too; TP-018 WatchDefaultRoute welcome in the port when needed (not now); route change is delete-then-add (brief fallback).
- [ ] Tests: interface recreate, outside removal, IPv6 takeover, ctx cancellation midway, third-party MTU change, IPv4 different prefix, normalized duplicate keys, two configurators in one namespace.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-007, branch: tp-007-netcfg-linux
- 2026-10-10 in-progress → review — make lint, make test, make lab-gotest (netcfg) green
- 2026-10-10 review → has-errors — review findings 1–12
- 2026-10-10 has-errors → in-progress — owner: agent-tp-007, fixing review findings
