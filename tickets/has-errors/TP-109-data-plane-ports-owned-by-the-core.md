---
id: TP-109
title: "Data-plane ports owned by the core"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: L
depends_on: [TP-075]
split_from: TP-083
refs: [S1, DESIGN#desktop-client]
owner: "agent-claude"
branch: "tp-109-data-plane-ports-owned-by-the-core"
---

## Goal
The data-plane core owns its port types; netcfg, routetable and dns adapt to them, matching transport, Inbound, blobs and routetable.Guard.

## Scope
- Move port types into `internal/dataplane`: an interface config, a route-table want/status and a resolver config holding only what the engine means.
- netcfg, routetable and dns adapt to those types; adapter-only fields (`Rule.Oif`, `Rule.Mark`, `Want.Upstreams`, the per-OS `netcfg.Survey` union) stay in the adapters.
- Stop naming adapter packages' types from the core (`engine.go` ~62, ~105, ~353; `routetable.go` ~18-19).
- Pattern: `transport.Dialer`/`Listener`/`Link`, `agent.Inbound`, `blobs.Store`, `routetable.Guard`.

## Out of scope
- Engine field split, connection state and node events: TP-110.
- Agent-layer status vocabulary, `waitLog` replacement and local API tables: TP-083.

## Acceptance
- [x] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [x] depguard rule in `.golangci.yml`: `internal/dataplane/*.go` may not import `routetable`, `dns` or `tun`

## Notes
- **Split (2026-10-18):** port ownership carved out of TP-083; lands before TP-083's remaining work.
- **Evidence on `rewrite`:** `EngineConfig.Interface` is `netcfg.Configurator` (`internal/dataplane/engine.go:62`); `DNS` is `interface{ Update(dns.Config) }` (`engine.go:105`); `RouteTable.Enforce` takes `routetable.Want` (`internal/dataplane/routetable.go:18-19`).
- **What landed:** the core's ports are `InterfaceConfigurator`/`InterfaceConfig` (`interface.go`), `RouteTable`/`RouteTableWant`/`RouteTableStatus` (`routetable.go`) and `Resolver`/`ResolverConfig`/`NameRoute` (`resolver.go`). The adapters are in `internal/agent/engineports.go`: `overlayInterface` (netcfg), `routeTable` (routetable, through `agent.RouteEnforcer`, the shape of `routetable.Enforcer`, which `Host.NewRouteTable` now returns) and `dnsResolver` (dns). netcfg, routetable and dns are unchanged.
- **Upstreams:** `Want.Upstreams` being adapter-only, `Engine.SetDirectUpstreams` moved to the agent's `routeTable` adapter (`runner.routes`): it remembers the last want the engine enforced and re-enforces it with new upstreams, as the engine did (sorted, deduplicated, kept before the first enforce, not re-enforced when unchanged). Its test moved with it (`internal/agent/engineports_test.go`). DESIGN.md "Route table on macOS" and "Engine and agent" say so.
- **depguard:** the rule (`dataplane-core-without-host-adapters`) covers the package's own non-test files (`**/internal/dataplane/*.go`, `!$test`). Tests are left out on purpose: `engine_lab_test.go` drives a real TUN and netcfg configurator (with a small adapter of its own, since dataplane may not import the agent).
- **Noticed, not done:** the core no longer imports `netcfg` either, so the rule could deny it too (the ticket names only routetable, dns and tun). `StepInterface`'s comment still says "(netcfg)". For TP-110: this branch touches `internal/agent/dataplane.go` in `runner` (a `routes` field) and `start` (wrapping the adapters).

## Review findings
- [ ] R1.1 internal/agent/engineports.go:78: a closed route-table adapter returns dataplane.ErrEngineClosed, but it isn't the engine (it may be closed on the NewEngine-failed path, where no engine existed): its own `errRouteTableClosed = errors.New("route table closed")`, engineports_test.go:72 updated; no caller relies on ErrEngineClosed there (the resolver's upstreams callback logs it).
- [ ] R1.2 .golangci.yml: the core rule also denies internal/dataplane/netcfg (desc: the engine's interface is its own InterfaceConfigurator port; the agent adapts netcfg to it), the ticket's first piece of evidence; the tun desc says which tun ("the agent creates the TUN; the engine takes golang.zx2c4.com/wireguard/tun's Device"). The Log says netcfg was added beyond the Acceptance text, and why; the bite check re-run for netcfg.
- [ ] R1.3 internal/dataplane/engine.go:36: the StepInterface comment says "(the InterfaceConfigurator)", not "(netcfg)".
- [ ] R1.4 internal/dataplane/engine_lab_test.go:~47: overlayInterface moves above labNode with its own doc ("netcfg's configurator as the engine's interface port (the agent's adapter, which this package can't import)"), the agent's shape (a field c, not an embedded type); labNode's doc restored.
- [ ] R1.5 Ticket Notes: "Noticed, not done" shrunk to what's left; one sentence on why the adapters live in internal/agent and not beside each package (they'd import the engine package: the layering upside down); the Goal's "netcfg, routetable and dns adapt to them" reconciled with "unchanged" in the Notes.
- [ ] R1.6 RouteEnforcer moves next to Host in internal/agent/platform.go: Host's contract, not an engine port.
- [ ] R1.7 internal/agent/engineports.go:59: `t.want = &w` keeps the engine's Overlay/Bypass slices, which the DNS goroutine reads later: cloned.
- [ ] R1.8 The port docs in interface.go:12, routetable.go:15 and resolver.go:10 name their adapters: a short signpost only if it reads like transport's ("implemented by …"); the Log says which.
- [ ] R1.9 internal/agent/resolver_test.go:476: wantsTable's doc says it records what reaches the host's route table, upstreams included, not what the engine enforces.

## Log
- 2026-10-18 created in backlog (split from TP-083, owner decision)
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-109-data-plane-ports-owned-by-the-core
- 2026-10-19 the core owns its ports (InterfaceConfigurator, RouteTable/RouteTableWant/RouteTableStatus, Resolver/ResolverConfig/NameRoute); internal/agent/engineports.go adapts netcfg, routetable and dns to them; Engine.SetDirectUpstreams moved to the agent's route-table adapter (865d176); DESIGN.md updated (f2478f1)
- 2026-10-19 depguard rule dataplane-core-without-host-adapters (f211ecc); it bites: with dataplane/dns, dataplane/routetable and dataplane/tun imported into internal/dataplane/doc.go, make lint exited 2 with 3 depguard findings; reverted
- 2026-10-19 checks at f2478f1 (git merge origin/rewrite: already up to date): make lint exit 0, make test exit 0, make lab-test exit 0 in 442s (LAB_P=1, another lab running; 35 node packages ok, lab suite ok). An earlier make lab-test at f2478f1 (LAB_P=4, 147s) exited 2 on blobs TestAPeerDroppedFromThePlanIsServedNoMore ("connection refused"); blobs doesn't depend on any changed package, and make lab-gotest PKG=./internal/dataplane/blobs then passed 3 of 3: a flake
- 2026-10-19 in-progress → review — not verified here: macOS (the route-table adapter's upstreams on a device: the agent's tests cover that they reach routetable.Want, as before)
- 2026-10-19 review → has-errors — review round 1: R1.1–R1.9 (design review; two reviewers said merge)
