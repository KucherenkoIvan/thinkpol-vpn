---
id: TP-026
title: "Censor modules: fully-encrypted heuristics and active prober"
milestone: M2
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024, TP-064, TP-089]
refs: [C4]
owner: ""
branch: ""
---

## Goal
The lab catches traffic that looks like random bytes and servers that don't behave like ordinary web servers.

## Scope
- The exemption rules from Wu et al., "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic" (USENIX Security 2023), on the first data packet of a flow: average set bits per byte, printable prefix, printable fraction, printable runs, TLS/HTTP fingerprints. Apply them to UDP flows too.
- Active prober: on suspected flows, connect to the server with replayed and random payloads; flag servers that answer unlike a normal web server (timeouts, resets, closing after N bytes).
- **JA3S/JA4S** for the server hello (extension order and ALPN included), compared with the camouflage site's fingerprint; the lab matrix uses these results honestly.
- The prober also flags the **upstream tell**, an entry that opens a connection to the camouflage target on every probe (independent design review, 2026-10-13).

## Acceptance
- [ ] a Shadowsocks-like random stream is flagged; HTTPS is not
- [ ] the prober tells a naive echo server from nginx
- [ ] the prober reports the server hello's JA3S/JA4S, extension order and ALPN against the camouflage site's, and detects an entry that opens an upstream connection to the camouflage target on every probe; the results are shown honestly in the matrix

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): prober covers the server-side fingerprint and the upstream-connection tell
- 2026-10-15 docs (backlog grooming): owns server JA3S/JA4S computation (TP-032 keeps client fingerprints and whitelist)
- 2026-10-15 depends_on TP-089 (split from TP-024 review)
