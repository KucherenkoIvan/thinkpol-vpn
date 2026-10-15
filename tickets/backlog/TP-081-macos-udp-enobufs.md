---
id: TP-081
title: "UDP send backpressure on macOS (ENOBUFS)"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: S
depends_on: []
refs: [C1, C3, C6, DESIGN#transports]
needs_human: macos
owner: ""
branch: ""
---

## Goal
On macOS, saturated tunnel uploads no longer drop UDP writes with ENOBUFS spam; sends use adequate socket buffers, brief wait or backpressure on ENOBUFS, and rate-limited error logging.

## Scope
Device runs 2–4 logged 288, 4070 and 2622 "link write failed … no buffer space available" (ENOBUFS) on the macOS client during the upload part of the speed test. The packet is dropped, and TCP inside the tunnel backs off. Upload was still close to direct in run 4 (90 vs 89 Mbit/s), so the impact is moderate. It also spams logs.

On darwin, set a larger `SO_SNDBUF` on the link socket (check what is set today). On ENOBUFS, wait briefly and retry, or apply backpressure, instead of dropping. Rate-limit the "link write failed" log for ENOBUFS.

## Acceptance
- [ ] unit test for the retry/backoff behaviour with a fake socket returning ENOBUFS
- [ ] device checklist: ENOBUFS count during the tunnel speed test drops by an order of magnitude, with upload not worse

## Notes

## Log
- 2026-10-15 created in backlog (device run 3 and 4 findings)
