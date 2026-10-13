---
id: TP-064
title: "Reality transport: Xray REALITY wire compatibility and using existing VLESS/Reality servers"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: L
depends_on: []
refs: [C2, DESIGN#transports]
owner: ""
branch: ""
---

## Goal
A written answer, with a prototype where it helps, to how thinkpol can use REALITY: the owner wants REALITY support and the `reality`-style transport is pulled forward. The `tls` transport's server side can't match its camouflage site's hello and opens an upstream connection per probe (independent design review, 2026-10-13); borrowing a real site's handshake removes both. Research first, then the findings become tickets.

## Scope
Questions to answer:
- **Our transport speaking REALITY.** Can a thinkpol transport speak Xray's REALITY handshake (borrowing a real site's TLS, no certificate of our own), so existing tooling and servers interoperate? What is on the wire, what keys and short ids does it need, and what would the transport's settings, credential and the camouflage target look like in the map?
- **Existing servers as entry or exit.** Can an existing VLESS/Reality server (for example a 3x-ui deployment) act as an entry or exit for thinkpol traffic, with VLESS UDP carrying our frames? What would the node owner configure, and what would the map say about such a node?
- **What is lost** against our own transport: need-to-know sections, per-space isolation and workers, the supervisor's authentication and fair share, traffic shaping (C6), telemetry, anything else.
- Licensing and dependency questions of reusing REALITY's Go code (Xray is Go): what can be vendored or imported, and what must be written again.

## Out of scope
- A **bridge** node type (a VLESS ingress routed into the overlay): considered and set aside as too complex for now. Revisit only if the answers above make it cheap.
- Implementing the transport: a ticket from the findings.

## Acceptance
- [ ] a findings note in this ticket's Notes answers each question above, with the recommendation and the follow-up tickets it proposes
- [ ] where a question needs it, a throwaway prototype in the lab (not merged into `internal/`) shows an interoperating handshake or says why it can't
- [ ] DESIGN.md's transports table reflects the result

## Notes
- Related: TP-028 (`tls`, whose server-side tells this addresses), TP-026 and TP-032 (the prober that measures them), PRD "Decisions" (Reality).

## Log
- 2026-10-13 created in backlog (TP-062)
