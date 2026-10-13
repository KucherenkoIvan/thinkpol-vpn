---
id: TP-061
title: "Security hardening from the independent code review (2026-10-13)"
milestone: M1
area: security
repo: thinkpol-vpn
size: M
depends_on: []
refs: [DESIGN#routing-rules-and-dns, DESIGN#desktop-client]
owner: "agent-hardening"
branch: "tp-061-security-hardening"
---

## Goal
The findings of the independent security code review of 2026-10-13 are fixed or written down as decisions: no known-vulnerable module in reachable code (and a lint step that keeps it so), a resolver that only accepts an upstream's answer from the server it asked, no integer conversion from wire or user input that can panic, a dev-only secrets seed that can't end up in a real map, and the review's smaller notes recorded where the code lives.

## Scope
- **Dependencies.** `google.golang.org/grpc` ≥ 1.83.1, `golang.org/x/net` ≥ 0.60.0, and any other module govulncheck flags in reachable code. A `make vulncheck` target (govulncheck, pinned in `make tools`), run from `make lint`.
- **Resolver upstreams** (`internal/dataplane/dns`, `exchange`): one connected UDP socket per upstream query, so the kernel picks a random ephemeral source port and only the asked server's address and port are delivered; the transaction-ID check stays; no answer from another server is accepted for that query; truncation, or a reply that fails the ID or question check, falls back to TCP. The remaining window is written down at the ID check. Tunnel and direct socket controls (marks, TUN binding) unchanged.
- **Integer conversions.** `TailLogs` clamps `lines` through uint64 before converting to `int`; a sweep of other conversions from wire or user input (proto getters, length fields, offsets) fixes any that could panic or go negative; the local API's gRPC server recovers handler panics.
- **Insecure secrets seed.** `dev map build -insecure-secrets-seed` is refused unless the spec declares `lab: true` (top level); the map itself is unchanged (no wire change); help text and a test.
- **Notes in code.** Local API client: the socket directory is the trust anchor. `blobs/serve.go`: the plan is the access control, by construction if cheap, else documented precisely. udp transport `wire.go`: send time is uint32 seconds, wraps in 2106, and `fresh()` tolerates it (verified).
- **DESIGN.md.** One sentence: the udp transport authenticates with an AEAD (XChaCha20-Poly1305 under credential-derived keys); NaCl sealed boxes are only used for map sections.

## Out of scope
- The review's macOS/Windows kill-switch note (TP-021, TP-047).
- DoT or DNS-over-TCP-only upstreams.

## Acceptance
- [ ] govulncheck before/after recorded in Notes; after: no vulnerability in reachable code
- [ ] `make vulncheck` exists, govulncheck pinned in `make tools`, run from `make lint`
- [ ] resolver: a spoofed answer from a different source is ignored and the real one is used; a matching answer from the right server is accepted; truncation and spoof-suspect replies fall back to TCP (tests)
- [ ] `TailLogs` clamps; sweep findings listed in Notes; local API gRPC server recovers panics (test)
- [ ] `dev map build -insecure-secrets-seed` refused without `lab: true` in the spec, accepted with it (test); help text updated
- [ ] the notes are in code comments; DESIGN.md sentence on the udp transport's AEAD
- [ ] `make lint`, `make test`, race on touched packages, and `make lab-gotest PKG=./internal/dataplane/dns/...` pass

## Notes

## Log
- 2026-10-13 created in in-progress — owner: agent-hardening, branch: tp-061-security-hardening
