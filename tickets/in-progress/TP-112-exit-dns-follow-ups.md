---
id: TP-112
title: "Exit DNS: follow-ups from TP-098's review"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-098]
refs: [R4, DESIGN#dns]
owner: "cursor-glm-tp-112"
branch: "tp-112-exit-dns-follow-ups"
---

## Goal
The exit-DNS code says what it does and handles the cases the review found.

## Scope
- The "running inside a worker" signal reuses `DataPlane.Forward` (`internal/agent/resolver.go` ~27-29, ~40; `servespace.go` ~117): give it its own field set only by `serveSpace` (e.g. `inWorker`), assert `serveSpace` sets it, and use it in the tests instead of `Forward`.
- `DESIGN.md` "Upstreams" bullet reads out of order and "those sockets" has no antecedent: direct upstream first (with its socket-mark sentence), then tunnel-bound names (a device's resolver binds its sockets to the exit to the TUN), then the exit's upstreams; "not asked" instead of "left out … never silently dropped".
- The defaults' reason is stated in five places (`resolver.go` ~18-24, ~190-207; `dataplane.go` ~72-76; `workerconfig.go` ~27-28): point the code at DESIGN instead; drop the "sandbox can't read" reason, which contradicts DESIGN.
- Removing the node from its space clears the refused count but not `refusedLogged` (`node.go` ~506): reset both, so rejoining with the same refused set logs again; add the test for the removal path.
- Defaults ignore the families the uplink carries: on an IPv4-only exit the dead Quad9 IPv6 entry is tried second and can stall past the device's 2 s timeout (`resolver.go` ~196-223; `dns/handle.go` ~165). Order or filter the defaults by the families the supervisor's egress carries.
- A server without egress still counts refused upstreams and reports `dns_upstream_refused`, though no device asks its resolver: report it only for exits.
- The refusal log's hint suggests `-egress-allowed` for every refused upstream, including metadata addresses (`resolver.go` ~226): don't suggest opening link-local/metadata.
- Nits: drop the redundant loop in `TestAWorkerResolvesThroughTheDefaultPublicUpstreams` after the exact-list check; `supervisor/isolation_test.go` uses neutral public addresses, not the agent's defaults; `isolation_linux.go` ~273 uses `slices.Concat` instead of `append` on the shared `egressBlocked`.

## Out of scope
- New exit-DNS behaviour beyond what TP-098 shipped; only review follow-ups listed above.

## Acceptance
- [ ] each scope item fixed or answered in the Log
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: TP-098's final review round (2026-10-18), split under the three-round cap.

## Log
- 2026-10-18 created in backlog (TP-098 review round 3)
- 2026-10-21 backlog → in-progress — owner: cursor-glm-tp-112, branch: tp-112-exit-dns-follow-ups
