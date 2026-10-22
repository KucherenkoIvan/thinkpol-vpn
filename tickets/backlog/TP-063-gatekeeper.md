---
id: TP-063
title: "Gatekeeper: pre-auth parsing out of the supervisor"
milestone: M2
area: agent
repo: thinkpol-vpn
size: L
depends_on: []
refs: [C2, N6, S1, docs/design/server-agent.md#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
Everything that parses unauthenticated, attacker-controlled bytes runs in an unprivileged **gatekeeper** process with no space keys beyond what verification needs, not in the root supervisor that holds every space's credential tables. One memory-safety bug in that path then costs the gatekeeper, not the node (independent design review, 2026-10-13). In M2 this is `udp`'s pre-auth filter; `reality` follows in TP-088, and `tls`'s ClientHello check moves with TP-028 after the MVP.

## Scope
- A gatekeeper process, started and watched by the supervisor, sandboxed like a worker (own user namespace and uid, no capabilities beyond binding what it was handed, `no_new_privs`, cgroup limits, restarted with backoff).
- Moves into it: datagram authentication, timestamp and replay filtering (and the connection-id routing that needs them), for `udp`.
- It holds only verifiers: for `udp`, the per-credential secret it needs and nothing else. No space keys, WireGuard keys or maps.
- Hands authenticated connections and datagrams to the right worker the way the supervisor does today (file descriptors and forwarded datagrams over sockets), and drops everything unauthenticated (a replay included).
- The supervisor keeps namespaces, the root firewall, fair share and the worker lifecycle.

## Out of scope
- `reality`'s session-id open and splice: TP-088.
- `tls`'s ClientHello peek and token check, with its asymmetric verifiers: TP-028, after the MVP.

## Acceptance
- [ ] the process that reads unauthenticated bytes runs unprivileged in its own sandbox; the root supervisor reads none
- [ ] a seizure check: the gatekeeper's memory holds no space keys and no map, only verifiers and the credential-to-space table it needs
- [ ] a malformed-input fuzz run of the gatekeeper's datagram-header parser is clean
- [ ] the two spaces on one listener tests (TP-010) pass unchanged

## Notes
- Source: DESIGN "Server agent" (pre-authentication parsing moves out of the root supervisor); the supervisor's shape today is in TP-010's ticket.
- Split before starting, with the `udp` move first.
- **TP-069 and TP-070:** their tests should move with the filter into the gatekeeper; name them here so implementers re-home tests instead of rewriting from scratch. No `depends_on` between those tickets and this one.

## Log
- 2026-10-13 created in backlog (TP-062)
- 2026-10-15 docs (backlog grooming): TP-069/TP-070 test re-home named in Notes
- 2026-10-15 docs (backlog grooming, review fixes): split note shortened
- 2026-10-15 docs (board op): rescoped to `udp` for M2 (decision 2026-10-15); TP-028 dropped from depends_on; `reality` → TP-088, `tls` part → TP-028
