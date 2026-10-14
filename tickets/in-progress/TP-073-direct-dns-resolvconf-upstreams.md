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
- [ ] nameservers from a rewritten resolv.conf go through the same stub filtering as `upstreamsFrom`
- [ ] a test: rewritten resolv.conf pointing at the local stub does not become a direct upstream

## Notes
- **Independent review (2026-10-15):** proven mismatch between `:225` and `:393`.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: agent-composer, branch: tp-073-resolvconf-upstreams
