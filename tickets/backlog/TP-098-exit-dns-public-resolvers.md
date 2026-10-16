---
id: TP-098
title: "Exits resolve through public resolvers by default"
milestone: M2
area: dataplane/dns
repo: thinkpol-vpn
size: S
depends_on: []
refs: [R4, DESIGN#dns]
owner: ""
branch: ""
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
- [ ] a server-mode exit with no `-dns-upstream` resolves tunnel-bound names through the default public upstreams. Lab: the lab's "public resolvers" are stand-ins on documentation addresses; the default list is injectable for the test
- [ ] a private or link-local upstream is reported in health and in the log, and isn't silently dropped
- [ ] the lab test from TP-023 (`TestDNSFollowsTheRulesOnAServerExit`) no longer needs `-egress-allowed` for DNS
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-023's round-2 correctness review: the worker's resolver takes the host resolvers minus loopback (`internal/agent/node.go` around 662-677), and the supervisor's isolation drops private and link-local destinations unless allowed (`internal/agent/supervisor/isolation_linux.go` around 131-146). Widening `-egress-allowed` to 169.254.0.0/16 would open cloud metadata services to every space, so it is no fix.
- The owner approved public resolvers as the default on 2026-10-16.

## Log
- 2026-10-16 created in backlog (TP-023 round-2 review)
