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

- [ ] reflected TCP, UDP and ICMPv6 (and ICMP/TCP/UDP over IPv4) packets carry a correct checksum, unit-tested with packets whose checksum field holds a wrong or partial value
- [ ] the device checklist: `dig @A6`, TCP to A6 and `ping6 A6` work, and the "bad checksum" counter doesn't grow (next device run)

## Notes

On macOS the node's overlay utun has IPv4 A4 (point-to-point to itself, route `A4 A4 UH utunN`) and IPv6 A6 (route `A6 link#N UHL lo0`). Packets the Mac sends to its own overlay addresses are written into the utun. The router reflects them back into the TUN when both source and destination are local addresses (`internal/dataplane/router/router.go`, reflection branch added in TP-019). That reaches the in-process DNS resolver on A4 for IPv4.

For IPv6 it fails: a `dig @A6` query was reflected (`router.reflected` +1), and the kernel counted UDP received over IPv6 with a bad checksum at the same moment, so the resolver on `[A6]:53 never saw it.

Root cause (inferred): XNU treats traffic to a local IPv6 address as loopback and may leave UDP/TCP checksums incomplete (offload / partial checksum) while still handing the packet to the utun. thinkpol wrote it back unchanged; on utun input the kernel verifies in software and drops it. IPv4 to A4 uses the real utun route and gets a full checksum.

Effect: anything on the Mac talking to its own overlay IPv6 is broken. A6 is often the second nameserver of the system resolver, so DNS failover is broken too.

## Log

- 2026-10-15 created in in-progress (split from TP-019 after device run 2; stacked on tp-019-macos-data-plane)
