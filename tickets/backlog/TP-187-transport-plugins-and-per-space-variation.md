---
id: TP-187
title: "Transport plugins and per-space variation"
milestone: later
area: dataplane/transport
repo: thinkpol-vpn
size: epic
depends_on: [TP-087, TP-044]
refs: [C2, C6, docs/design/transports.md#plugins-after-the-mvp]
owner: ""
branch: ""
---

## Goal
Transports can run as out-of-process plugins in any language, and the built-in transports' settings vary per space, as docs/design/transports.md "Plugins (after the MVP)" records (owner, 2026-11-07).

## Scope (split before starting)
- Out-of-process transport plugins, meeting every requirement in the design section (control over gRPC on a private channel, packets over an anonymous socket pair, an unprivileged non-dumpable plugin user, bounded queues, advisory link claims, secrets only over the control channel, a dead plugin takes its link down with the kill switch holding, plugins named by hash and delivered signed).
- One possible adapter: Tor's Pluggable Transports spec (obfs4, webtunnel, Snowflake).
- Per-space variation of the built-in transports' settings, picked by the controller within safe ranges.

## Out of scope
- Mobile builds: they compile transports in.
- The `reality` transport: TP-087.

## Acceptance
- [ ] split into tickets, each with acceptance taken from the design section

## Notes
- Source: owner decision 2026-11-07 (docs/design/transports.md, "Plugins (after the MVP)").
- Variation alone isn't the defence: generic "fully encrypted / unknown protocol" classifiers flag rare protocols; imitation of common traffic is the main defence.

## Log
- 2026-11-07 created in backlog (owner decision on transport plugins)
