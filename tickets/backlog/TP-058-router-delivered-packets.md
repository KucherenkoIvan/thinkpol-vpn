---
id: TP-058
title: "Router Delivered counter counts bytes on Linux TUN"
milestone: M1
area: dataplane/router
repo: thinkpol-vpn
size: S
depends_on: [TP-008]
owner: ""
branch: ""
---

## Goal
The router's `Delivered` counter counts packets on every platform, as its name and the status say. On a Linux TUN with offloads the counter counts bytes instead: the TUN coalesces packets in place and its `Write` returns a byte count, and `Delivered` takes that count. TP-014 left the note that `Delivered` counts bytes there (`router` egress status), and the mismatch was reported by TP-014's review. After this, `thinkpol status` and the local API show packets on Linux too.

## Scope
- On the Linux TUN path, `Delivered` increments by one per packet written, whatever the `Write` return value means (bytes, or the number of coalesced segments). The router counts the packets it handed over, not the return value.
- Check the other `Delivered` consumers (local API conversion, status rendering, `thinkpol status`) for the same unit assumption and fix any that assume bytes.

## Out of scope
- Byte counters: `RxBytes`/`TxBytes` on peers and the path counters keep their meaning.
- Offload behaviour itself (TP-018 and the TUN setup are not changed here).

## Acceptance
- [ ] unit test on the Linux TUN path: with offloads on, a batch of N packets written through the router advances `Delivered` by N, not by the bytes `Write` returns
- [ ] status and the local API report `Delivered` as packets on Linux (a test on the converted value)
- [ ] `make lint` and `make test` pass

## Notes
- Reported by TP-014 review (`Delivered` counts bytes on a TUN with offloads; noted as a TP-008 leftover for TP-018).

## Log
- 2026-10-12 created in backlog
