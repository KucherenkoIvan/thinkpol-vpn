---
id: TP-079
title: "macOS: reflected packets to the node's own IPv6 fail the checksum"
milestone: M1
area: dataplane/router
repo: thinkpol-vpn
size: S
depends_on: [TP-019]
refs: [D1]
needs_human: macos
owner: agent-composer
branch: tp-079-macos-own-ipv6-reflection
---

## Goal

On macOS, packets the node sends to its own overlay IPv6 are reflected back into the utun with a valid transport checksum so the kernel delivers them (DNS on the overlay IPv6, TCP, ping6) instead of dropping them with a bad UDP/TCP checksum.

## Scope

In the router reflection path (`internal/dataplane/router`), before writing a reflected packet back to the TUN, recompute checksums from scratch for IPv4 and IPv6: TCP, UDP, ICMP/ICMPv6, and the IPv4 header checksum. Pure Go, reflection path only.

## Out of scope

Non-reflection paths; changing how macOS routes local overlay traffic; device verification (checklist in acceptance, human run).

## Acceptance

- [x] reflected TCP, UDP and ICMPv6 (and ICMP/TCP/UDP over IPv4) packets carry a correct checksum, unit-tested with packets whose checksum field holds a wrong or partial value (`checksum_test.go`, `TestReflectedIPv6UDPFixesChecksum` in `router_test.go`; `make test`, `go test -race ./internal/dataplane/checksum/... ./internal/dataplane/router/...`)
- [x] the device checklist: `dig @A6`, TCP to A6 and `ping6 A6` work, and the "bad checksum" counter doesn't grow (device run 4: N10 and N12 PASS; no checksum drops)

## Review findings

- [x] 1. BLOCKER — IPv4 fragments and IPv6 fragment header: skip L4 / leave packet unchanged (`checksum.go`)
- [x] 2. BLOCKER — IPv6 extension length byte arithmetic infinite loop (`checksum.go:144`, `checksum_test.go:108` `TestFixExtLen255Terminates`)
- [x] 3. SHOULD-FIX — router wiring test with bad IPv6 UDP checksum (`router_test.go`)
- [x] 4. SHOULD-FIX — independent test oracle and extra vectors (`checksum_test.go`)
- [x] 5. SUSPICION — clamp packet length to IP Total Length / IPv6 payload (`checksum.go`)
- [x] 6. NITS — `router.go` comment; `DESIGN.md` reflection checksum clause

## Notes

On macOS the node's overlay utun has IPv4 A4 (point-to-point to itself, route `A4 A4 UH utunN`) and IPv6 A6 (route `A6 link#N UHL lo0`). Packets the Mac sends to its own overlay addresses are written into the utun. The router reflects them back into the TUN when both source and destination are local addresses (`internal/dataplane/router/router.go`, reflection branch added in TP-019). That reaches the in-process DNS resolver on A4 for IPv4.

For IPv6 it fails: a `dig @A6` query was reflected (`router.reflected` +1), and the kernel counted UDP received over IPv6 with a bad checksum at the same moment, so the resolver on `[A6]:53 never saw it.

Root cause (inferred): XNU treats traffic to a local IPv6 address as loopback and may leave UDP/TCP checksums incomplete (offload / partial checksum) while still handing the packet to the utun. thinkpol wrote it back unchanged; on utun input the kernel verifies in software and drops it. IPv4 to A4 uses the real utun route and gets a full checksum.

Effect: anything on the Mac talking to its own overlay IPv6 is broken. A6 is often the second nameserver of the system resolver, so DNS failover is broken too.

- **Device run 4 (2026-10-15):** N10 and N12 PASS — TCP, `ping6` and `dig` to the node's own overlay IPv6 work; `router.reflected` grows; checksum counters show no drops; IPv6 overlay names resolve.

## Log

- 2026-10-15 created in in-progress (split from TP-019 after device run 2; stacked on tp-019-macos-data-plane)
- 2026-10-15 in-progress → review — unit acceptance checked; device checklist pending (`needs_human: macos`); `make test`, `go test -race ./internal/dataplane/router/...` pass
- 2026-10-15 review → has-errors — review round 2 findings recorded
- 2026-10-15 has-errors → in-progress — fix round 2
- 2026-10-15 in-progress → review — round 2 fixes; `make test` pass; `make lint` golangci green; `buf breaking` on `localapi.proto` field 6 inherited from base
- 2026-10-15 review follow-up: ext-len test reproduces the loop; router test flips checksum bytes; checksumtest package
- 2026-10-15 device run 4: own IPv6 TCP/ping6/dig work on the device
- 2026-10-15 merged into rewrite (review → done)
