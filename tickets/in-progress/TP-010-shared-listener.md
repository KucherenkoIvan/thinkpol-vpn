---
id: TP-010
title: "Shared listener and connection handoff"
milestone: M0
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-005, TP-009]
refs: [N6, DESIGN#server-agent-one-worker-per-space]
owner: "agent-tp-010"
branch: "tp-010-shared-listener"
---

## Goal
The node's public address belongs to the supervisor, which authenticates every connection and hands it to the right space's worker.

## Scope
- Supervisor listens on the configured public ports of each transport.
- Runs the transport's authentication, maps the credential to a space, hands the connection over: stream connections by passing the file descriptor (`SCM_RIGHTS`), datagram flows by forwarding per connection id over the worker socket.
- Unauthenticated connections go to the camouflage handler and never reach a worker.
- Per-space credential tables loaded from each space's map.

## Acceptance
- [ ] in the lab, two spaces on one server (hand-made maps): each worker receives only its own links
- [ ] bad credentials never reach any worker

## Notes
- **Decided in the TP-005 review (2026-10-10):** the tls auth token rides in the ClientHello (e.g. an HMAC of the credential and a coarse timestamp in the legacy session id, via uTLS). The supervisor peeks at the ClientHello without terminating TLS and keeps a replay cache. Authenticated: it hands the fd plus the consumed bytes to the space's worker, which terminates TLS with its self-signed, pinned certificate. Anything else is proxied whole to the camouflage target, so probes see the real site's certificate. See DESIGN.md "Server agent: one worker per space".
- **Port seams (TP-005):** `transport.Routable.Router(peers)` gives a `transport.Router`. Use `RouteDatagram(d)` to authenticate a datagram (tag and timestamp) and get its `Identity`, then forward it untouched over the worker socket. On the worker side, `udp.Transport.ListenOn(pc, ListenConfig{Peers, Camouflage})` serves a `net.PacketConn` fed by the supervisor. `RouteStream(conn)` and `transport.HandoffListener.ServeStream(conn, consumed)` are the stream side, implemented here and in TP-028. `udp/router_test.go` is a working in-process sketch.
- When merging the spaces' tables into one `Peers`, stamp `Identity.Space` from the map it came from, never from the map's contents. Charge a space's fair-share bucket after its worker accepts a datagram. A credential shared by two entries is dropped for both and reported (`Router.Rejected`).
- **Replays and fair share (TP-005 delta review):** `Router.RouteDatagram` keeps no replay state, so it forwards replays of the last five minutes to the worker, which drops them. Those datagrams cost the worker a decryption, but charging fair share after the worker accepts means nothing charges for them. If that matters under load, give the supervisor a small replay filter (per credential, a window of recently forwarded nonces or counters) in front of the worker socket.

## Log
- 2026-10-10 created in backlog
- 2026-10-11 backlog → in-progress — owner: agent-tp-010, branch: tp-010-shared-listener
