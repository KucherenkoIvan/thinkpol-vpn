---
id: TP-026
title: "Censor modules: fully-encrypted heuristics and active prober"
milestone: M2
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024]
refs: [C4]
owner: ""
branch: ""
---

## Goal
The lab catches traffic that looks like random bytes and servers that don't behave like ordinary web servers.

## Scope
- The exemption rules from Wu et al., "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic" (USENIX Security 2023), on the first data packet of a flow: average set bits per byte, printable prefix, printable fraction, printable runs, TLS/HTTP fingerprints. Apply them to UDP flows too.
- Active prober: on suspected flows, connect to the server with replayed and random payloads; flag servers that answer unlike a normal web server (timeouts, resets, closing after N bytes).

## Acceptance
- [ ] a Shadowsocks-like random stream is flagged; HTTPS is not
- [ ] the prober tells a naive echo server from nginx

## Log
- 2026-10-10 created in backlog
