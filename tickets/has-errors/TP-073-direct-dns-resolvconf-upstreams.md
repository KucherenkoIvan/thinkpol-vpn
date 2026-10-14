---
id: TP-073
title: "Direct DNS upstreams from a rewritten resolv.conf are not filtered"
milestone: M2
area: dataplane/dns
repo: thinkpol-vpn
size: S
depends_on: []
refs: [N3, R4, DESIGN#routing-rules-and-dns]
owner: agent-composer
branch: tp-073-resolvconf-upstreams
---

## Goal
Direct DNS upstreams taken from a rewritten `resolv.conf` are filtered the same way as upstreams discovered elsewhere.

## Scope
- `dns/resolvconf.go:225` passes a rewritten resolv.conf's nameservers to `Upstreams` unfiltered, while `upstreamsFrom` (`:393`) strips the resolved stub, so an outside rewrite to `127.0.0.53` silently kills direct DNS.

## Out of scope
- Full resolv.conf watcher redesign.

## Acceptance
- [x] nameservers from a rewritten resolv.conf go through the same stub filtering as `upstreamsFrom` — `internal/dataplane/dns/resolvconf.go:227` via `upstreamsFromContent`, shared with `upstreamsFrom` at `:402`
- [x] a test: rewritten resolv.conf pointing at the local stub does not become a direct upstream — `TestARewrittenResolvConfFiltersStubUpstreams` (`internal/dataplane/dns/resolvconf_test.go:168`)

## Review findings
- [ ] Empty filtered upstreams on external rewrite must keep the previous upstreams and Warn (not call `Upstreams([])`); test must assert kept upstreams (`resolvconf.go`, `resolvconf_test.go`)
- [ ] Known gap (no watcher redesign): stub uplink read once; after rewrite `r.original` is stub content so `apply` never calls `Upstreams` again; resolved watcher only when `r.uplink` at `SetSystem`; later DHCP/resolved changes leave direct DNS stale until restart — document in Notes for follow-up
- [ ] Resolved watcher: route uplink nameservers through `upstreamsFromContent` (`system_linux.go`)
- [ ] DESIGN.md: stub never a direct upstream; empty uplink keeps previous upstreams
- [ ] Ticket Notes: record resolved watcher / stub-read-once gap for follow-up

## Notes
- **Independent review (2026-10-15):** proven mismatch between `:225` and `:393`.
- Extracted `upstreamsFromContent`; `resolvConf` keeps the resolved uplink path for stub-only fallback; `Upstreams` on an external rewrite now uses the same filter as `SystemUpstreams`.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: agent-composer, branch: tp-073-resolvconf-upstreams
- 2026-10-15 in-progress → review — filter rewritten resolv.conf upstreams through `upstreamsFromContent`; make lint, make test pass
- 2026-10-15 review → has-errors — reviewer: empty stub fallback cleared upstreams; resolved watcher unfiltered; DESIGN gap
