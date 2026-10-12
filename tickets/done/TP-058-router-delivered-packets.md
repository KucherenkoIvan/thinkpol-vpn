---
id: TP-058
title: "Router Delivered counter counts bytes on Linux TUN"
milestone: M1
area: dataplane/router
repo: thinkpol-vpn
size: S
depends_on: [TP-008]
owner: agent-small-fixes
branch: tp-058-router-delivered-packets
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
- [x] unit test on the Linux TUN path: with offloads on, a batch of N packets written through the router advances `Delivered` by N, not by the bytes `Write` returns
- [x] status and the local API report `Delivered` as packets on Linux (a test on the converted value)
- [x] `make lint` and `make test` pass

## Notes
- Reported by TP-014 review (`Delivered` counts bytes on a TUN with offloads; noted as a TP-008 leftover for TP-018).
- **Done:** `Egress.Write` adds the number of packets it hands to the TUN (`len(out)`, after the `NotLocal` filter) to the egress's and the router's `Delivered`, never `Write`'s return value. wireguard-go's Linux `NativeTun.Write` returns bytes with or without offloads (it sums each `write(2)`), and on an error joins the failed packets' errors without saying which got through, so a write that fails counts none of its packets (`Delivered` and `Forwarded` alike; before, `Delivered` took the byte count of the ones that went). Doc comments on `Counters.Delivered` and `EgressStatus.Delivered` say so; the local API's `Egress` message says its counts are packets (`make proto`).
- **Consumers:** the local API copies `Router.Delivered` and `EgressStatus.Delivered` unchanged; `thinkpol status` doesn't print them. Found on the way: `thinkpol status` listed `router.forwarded` under "dropped" (it wasn't in `trafficCounters`); it is traffic now.
- **Tests:** `router.TestDeliveredCountsPacketsWhateverTheTUNReports` (a TUN reporting bytes, like Linux's: 10 packets → `Delivered` 10, was 10280; a failed write adds none); `router.TestDeliveredCountsPacketsOnALinuxTUN` (lab: a real TUN with offloads in a throwaway namespace, which reports a batch of 16 UDP datagrams as 16608; `Delivered` 16, was 16608); `localapi.TestDeliveredPacketsReachTheStatus` (the converted `router.delivered`, `router.forwarded` and egress `delivered` are packets, and `thinkpol status` shows none of them as dropped; failed before on both counts).

## Log
- 2026-10-12 created in backlog
- 2026-10-12 backlog → in-progress — owner: agent-small-fixes, branch: tp-058-router-delivered-packets
- 2026-10-12 in-progress → review — every acceptance box checked; `make lint`, `make test`, `go test -race` on router and localapi, and `make lab-gotest PKG=./internal/dataplane/router/` (the Linux TUN test 5/5) pass
- 2026-10-12 review → done — merged into rewrite
