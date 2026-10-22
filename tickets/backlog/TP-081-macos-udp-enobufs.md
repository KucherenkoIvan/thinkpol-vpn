---
id: TP-081
title: "UDP send backpressure on macOS (ENOBUFS)"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: S
depends_on: [TP-019, TP-087]
refs: [C1, C3, C6, docs/design/transports.md#transports]
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
- **Count correction (cross-model analysis):** run 4 had 1311 ENOBUFS lines, not 2622. The kit counted two log files, one of which is a prefix of the other. All of them fell in the last ~5 s of the upload phase, and upload goodput still matched the direct uplink (90 vs 89 Mbit/s), so the impact on run 4's throughput was small.
- The kit's 'udp dropped due to full socket buffers' counter is receive-side and can't see these send-side drops.

## Log
- 2026-10-15 created in backlog (device run 3 and 4 findings)
- 2026-10-15 docs: ENOBUFS count corrected
- 2026-10-15 docs (backlog grooming): depends on TP-019 for the device acceptance box
- 2026-10-23 docs: waits for the `reality` transport (TP-087): the owner doesn't want plain `udp` load on the network for speed tests (TP-082 question 6)
