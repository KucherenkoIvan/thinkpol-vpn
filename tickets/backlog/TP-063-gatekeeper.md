---
id: TP-063
title: "Gatekeeper: pre-auth parsing out of the supervisor"
milestone: M2
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-028]
refs: [C2, N6, S1, DESIGN#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
Everything that parses unauthenticated, attacker-controlled bytes runs in an unprivileged **gatekeeper** process with no space keys beyond what verification needs, not in the root supervisor that holds every space's credential tables. One memory-safety bug in that path then costs the gatekeeper, not the node (independent design review, 2026-10-13).

## Scope
- A gatekeeper process, started and watched by the supervisor, sandboxed like a worker (own user namespace and uid, no capabilities beyond binding what it was handed, `no_new_privs`, cgroup limits, restarted with backoff).
- Moves into it: the ClientHello peek and token check, datagram authentication, timestamp and replay filtering (and the connection-id routing that needs them), for `udp` and `tls`.
- It holds only verifiers: for `tls`, asymmetric credentials (a public key per credential in the listener's section, so the node can't forge a client); for `udp`, the per-credential secret it needs and nothing else. No space keys, WireGuard keys or maps.
- Hands authenticated connections and datagrams to the right worker the way the supervisor does today (file descriptors and forwarded datagrams over sockets), and everything unauthenticated to the camouflage (a replay included, see TP-028).
- The supervisor keeps namespaces, the root firewall, fair share and the worker lifecycle.

## Out of scope
- The `tls` transport itself and its asymmetric token format: TP-028 (this ticket moves where it is checked).

## Acceptance
- [ ] the process that reads unauthenticated bytes runs unprivileged in its own sandbox; the root supervisor reads none
- [ ] a seizure check: the gatekeeper's memory holds no space keys and no map, only verifiers and the credential-to-space table it needs
- [ ] a malformed-input fuzz run of the gatekeeper's parsers (ClientHello peek, datagram header) is clean
- [ ] the two spaces on one listener tests (TP-010, TP-028) pass unchanged

## Notes
- Source: DESIGN "Server agent" (pre-authentication parsing moves out of the root supervisor); the supervisor's shape today is in TP-010's ticket.

## Log
- 2026-10-13 created in backlog (TP-062)
