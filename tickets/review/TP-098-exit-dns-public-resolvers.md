---
id: TP-098
title: "Exits resolve through public resolvers by default"
milestone: M2
area: dataplane/dns
repo: thinkpol-vpn
size: S
depends_on: []
refs: [R4, DESIGN#dns]
owner: "claude-tp098"
branch: "tp-098-exit-dns-public-resolvers"
---

## Goal
An exit resolves tunnel-bound names on any host out of the box: a cloud VPS (AWS, GCP, Azure, OCI) or a box on a home LAN. Today its worker asks the host's own resolvers. On those hosts the resolvers sit on private or link-local addresses, which the worker's isolation firewall rightly refuses, so every tunnel-bound name fails for every device. It fails closed, so nothing leaks, but R4 doesn't work there.

## Scope
- Default upstreams for an exit's resolver: well-known public resolvers on both families: Quad9 (9.9.9.9, 2620:fe::fe), then Cloudflare (1.1.1.1, 2606:4700:4700::1111). The host's resolvers are not used by default. `-dns-upstream` still overrides.
- An upstream the worker's egress refuses (private, link-local, metadata, anything `-egress-allowed` doesn't open) is refused at start or at a config change, with a health problem (`dns_upstream_unreachable` or similar) and a log line saying why. It is never silently dropped.
- DESIGN.md's DNS section ("Upstreams", which today says the exit asks "the host's non-loopback resolvers") states the new default and why: the host's resolver is private on most clouds, and the worker's isolation must not be widened to reach it.

## Out of scope
- Encrypted upstreams (DoT/DoH) from the exit: later.
- The device side's domestic upstream: unchanged.

## Acceptance
- [x] unit tests: with no `-dns-upstream`, the worker's upstreams are the default public list on both families, and the host's resolvers are not used; with `-dns-upstream`, the configured ones — `TestAWorkerResolvesThroughTheDefaultPublicUpstreams` (internal/agent/resolver_test.go); the host-resolver path is gone from the code
- [x] the upstream check uses the same blocked-destination list as the worker's egress (`egressBlocked` plus `EgressAllowed`), not a copy, so the two can't drift: unit tests show the defaults pass and private, link-local and metadata upstreams are refused unless `EgressAllowed` names them — `supervisor.EgressRefused` (internal/agent/supervisor/isolation.go) over the one `egressBlocked`, which the linux isolation also builds from; `TestPublicDestinationsPassTheEgress`, `TestTheEgressRefusesWhatTheIsolationDropsUnlessAllowed` (supervisor/isolation_test.go), and the allowed-opens-it case in `TestAnUpstreamTheEgressRefusesIsReportedNotSilentlyDropped`
- [x] a private or link-local upstream is reported in health and in the log, and isn't silently dropped — `workerUpstreams` logs each refused one with its address and why; health problem `dns_upstream_refused` (internal/agent/status.go) at degraded, asserted in `TestAnUpstreamTheEgressRefusesIsReportedNotSilentlyDropped`
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-023's round-2 correctness review: the worker's resolver takes the host resolvers minus loopback (`internal/agent/node.go` around 662-677), and the supervisor's isolation drops private and link-local destinations unless allowed (`internal/agent/supervisor/isolation_linux.go` around 131-146). Widening `-egress-allowed` to 169.254.0.0/16 would open cloud metadata services to every space, so it is no fix.
- The owner approved public resolvers as the default on 2026-10-16.
- No lab traffic test for the defaults (owner, 2026-10-18). The lab already proves that a worker's resolver asks its configured upstream (`TestDNSFollowsTheRulesOnAServerExit`) and that the egress passes what isn't blocked (`TestEgressThroughAnExit`). The new parts are a default list and a check, both unit-testable. The lab DNS test keeps `-dns-upstream` with `-egress-allowed`, because the lab's resolvers are on private addresses; that now also exercises "allowed opens it".
- Known gap (not in scope): a server whose worker has no egress grant drops even public upstreams; health doesn't say so. Partial and total refusal look the same in health.

## Log
- 2026-10-16 created in backlog (TP-023 round-2 review)
- 2026-10-18 acceptance narrowed to unit tests; no lab stand-in resolvers (owner)
- 2026-10-18 backlog → in-progress — owner: claude-tp098, branch: tp-098-exit-dns-public-resolvers
- 2026-10-18 the defaults are Quad9 then Cloudflare, both families, port 53 (defaultWorkerUpstreams, internal/agent/node.go); the host's resolvers are no longer asked at all (the systemUpstreams wiring left serverSpaces)
- 2026-10-18 the blocked-destination list and a pure predicate (supervisor.EgressRefused) moved from isolation_linux.go into egress.go, which every OS builds; the isolation's space_out chain and the upstream check use the same list, so the two can't drift
- 2026-10-18 a refused upstream is not configured: logged with its address and a hint, and health says dns_upstream_refused (degraded) while any are refused; Status.DNSUpstreamsRefused counts them; cleared when nothing is refused or the worker stops
- 2026-10-18 DESIGN.md DNS "Upstreams" states the new default and why; the TP-023 caveat there is replaced (no other DESIGN section touched, TP-099 edits in parallel)
- 2026-10-18 tests: TestAWorkerResolvesThroughTheDefaultPublicUpstreams, TestAnUpstreamTheEgressRefusesIsReportedNotSilentlyDropped (internal/agent/resolver_test.go); TestTheDefaultUpstreamAddressesPassTheEgress, TestTheEgressRefusesWhatTheIsolationDropsUnlessAllowed (internal/agent/supervisor/egress_test.go)
- 2026-10-18 make lint, make test pass; timed full lab suite (make lab-test LAB_P=1 plus -v): lab 212s, gotest 341s, both exit 0, no failures; TestDNSFollowsTheRulesOnAServerExit and TestEgressThroughAnExit passed unchanged (the lab DNS test keeps -dns-upstream with -egress-allowed)
- 2026-10-18 in-progress → review — branch tp-098-exit-dns-public-resolvers @ ea4a60a
- 2026-10-18 review → in-progress — owner: claude-tp098, round 2: review findings
- 2026-10-18 round-2 fixes: a server's resolver with every upstream refused has none and never asks the host's resolvers (TestAWorkerWithEveryUpstreamRefusedHasNone, resolver_test.go); refused upstreams are logged once per change of the refused set, not on every apply; Status.DNSUpstreamsRefused is a count; serverSpaces.defaultUpstreams deleted (defaultWorkerUpstreams and workerUpstreams moved to resolver.go, next to the DNS wiring); supervisor/egress.go → isolation.go, and EgressRefused refuses a zoned address; the -dns-upstream help and DESIGN.md's DNS section say the new default
- 2026-10-18 make lint, make test pass; make lab-test LAB_P=1 GOFLAGS=-p=4 passes on ce8131d (2026-10-18 14:42 +05, gotest ok, 34 packages, no failures)
- 2026-10-18 in-progress → review — branch tp-098-exit-dns-public-resolvers @ ce8131d
