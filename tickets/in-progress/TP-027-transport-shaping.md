---
id: TP-027
title: "Transport shaping contract"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: [TP-005]
refs: [C6, DESIGN#transports]
owner: "agent-tp-027"
branch: "tp-027-transport-shaping"
---

## Goal
Transports own traffic shape: padding, batching and timing are part of the transport contract, configured per link.

## Scope
- Shaping settings per link from the map: padding (none, to buckets, random range), batching window, timing jitter, idle cover traffic on/off.
- A reusable shaping layer transports can opt into; overhead metrics.
- Conservative defaults; tuning is lab work.

## Acceptance
- [x] conformance suite extended with shaping cases — `transporttest.Harness{Shaping, Refused, Transport}` applies a shaping to every link of the suite, plus cases `ControlPackets`, `ShapingOneSided`, `ShapingChange`, `ShapingRefused` (invalid shapings always, the adapter's `Refused` list: Dial, CheckEndpoint, CheckInbound and the listener all refuse) and `Overhead` (MTU budget). udp runs the suite unshaped (IPv4, IPv6) and under bucket and random padding (`TestConformance`, `TestConformanceShaped`); memory runs it with every kind of shaping refused.
- [x] padding visibly changes the packet-length distribution in a lab capture — `lab/shaping_test.go` (`TestShapingCapture`, `go test -tags lab -run TestShapingCapture ./lab/`): device-a sends 87 WireGuard-like packet sizes × 3 through the router to server-1. Captured at the router: unshaped, 261 datagrams in 86 sizes (124…1452, each packet + 74); padded to buckets 128/256/512/1024/1452, 261 datagrams in 5 sizes (128:3 256:33 512:48 1024:96 1452:81), at 37.7 % overhead against 10.7 % unshaped. On loopback, `udp.TestPaddingHidesPacketSizes` checks the same both ways, and that random padding spreads one packet size over ≥ 50 datagram sizes in 100 sends.

## Notes
**The contract** (`internal/dataplane/transport/shaping.go`, proto `proto/thinkpol/transport/v1/shaping.proto`):
- `Shaping{Padding, BatchWindow, Jitter, CoverInterval}`, comparable (TP-006 compares it with `==`). `Padding{Mode PadNone|PadToBuckets|PadRandom, Buckets [16]uint16, Min, Max uint16}`; `transport.Buckets(sizes...)` builds one. Sizes are of the wire unit a capture sees (datagram payload; for stream transports the record). Buckets: grow to the smallest bucket that holds the unit, larger units go as they are. Random: add uniform [Min, Max] bytes. Limits for every transport: buckets strictly ascending, ≤ 16; batch window and jitter ≤ 1 s, cover interval 10 ms … 1 h, whole microseconds. `Validate`, `IsZero`, `Padding.Size`, `Padding.Growth`.
- **Per end, no negotiation.** Each end shapes what it sends: `DialConfig.Shaping` (dialing end), `PeerLink.Shaping` (listening end). Receivers undo shaping from the wire format alone, so the ends needn't agree (conformance `ShapingOneSided`). A table change re-shapes a live link.
- **Encoding and versioning.** `thinkpol.transport.v1.Shaping` (oneof padding {buckets, random}, `batch_window_us`, `jitter_us`, `cover_interval_us`); empty bytes = none. `transport.ParseShaping` decodes it strictly: unknown fields anywhere → `ErrUnsupportedShaping`, so an old node refuses a link rather than shape less than asked; new settings are new fields. `Shaping.Marshal` encodes (deterministic).
- **Where the map carries it:** a new `shaping` bytes field on `Endpoint` (5) and `InboundLink` (6), Go `netmap.Endpoint.Shaping` / `InboundLink.Shaping`, bounded like settings (4 KiB), next to (not inside) the transport-owned `settings`. This departs from TP-003's note that `InboundLink.settings` would carry shaping: the port already had `Shaping` as a sibling of `Settings`, and the engine needs the decoded shaping for the MTU budget without parsing transport-owned bytes. netmap.proto's comment and DESIGN are updated.
- **Refuse, never weaken.** `ShapingSupport{Padding, Batching, Jitter, Cover}.Check(s)` validates and refuses what an adapter doesn't implement (`ErrUnsupportedShaping`; nonsense is `ErrInvalidShaping`). Adapters call it from `CheckEndpoint`/`CheckInbound`; listeners skip and report such peer links.
- **MTU.** `Overhead(s)` = the fixed cost plus the most random padding adds. Under buckets a packet that fits a path can still round up past it, so the budget is `transport.MaxPacket(t, s, unit)` (unit = path MTU − IP − UDP): the largest bucket ≤ unit if some bucket is above it, minus Overhead; 0 if every bucket is above.
- **Overhead metrics.** `transport.SendMeter` / `SendStats{Units, Packets, PacketBytes, PaddingBytes, WireBytes}.Overhead()`. udp: `Listener.Sent()` and the dial link's `Sent()`.
- **Control packets (from the TP-006 review).** `transport.ControlWriter{WriteControl(p)}` is an optional Link interface; `transport.WriteControl(link, p)` uses it or falls back to `WritePacket`. A control packet keeps a link warm or measures it: the transport may pad and jitter it like data, hold it up to `transport.MaxControlHold` (500 ms) to ride with the next data or cover unit, or send it as the cover unit it would send anyway; the far end reads an ordinary packet. No adapter implements it yet (udp has no batching or cover to fold into).

**udp** (wire format changed; nothing is deployed):
- `conn id | nonce | XChaCha20-Poly1305(sender | sent | counter | frames | padding)`, frame = `length[2] | packet`. A zero length or < 2 bytes left ends the frames; padding is zeros inside the AEAD (authenticated, invisible but for the datagram length). Senders put one packet per datagram; receivers take any number, and none = a cover datagram (passes every check, counted in `Counters.Cover`, keeps a link's address current, opens no link). Malformed frames are dropped as unauthenticated. So batching and cover can arrive later without changing receivers.
- Implements padding (buckets ≤ 8778 bytes, random ≤ `MaxRandomPadding` = 512, which keeps datagrams under macOS's 9216-byte default); refuses batching, jitter and cover. Overhead 74 bytes (+ random Max). `Counters.Delivered` now counts packets.

**For TP-008 / the engine (and TP-006's `PathConfigFrom`):** fill `DialConfig.Shaping` / `PeerLink.Shaping` from `transport.ParseShaping(endpoint.Shaping)` / `(inbound.Shaping)`, then `CheckEndpoint` / `CheckInbound` as now. udp's overhead is 74, not 72 (TP-006's Notes): TUN MTU for a 1500-byte IPv6 path over unshaped udp is 1328; with shaping use `transport.MaxPacket(t, s, 1452) − path.HeaderSize − 32`.

**For TP-006 / TP-031 (path layer):** send probes and probe replies with `transport.WriteControl`, never `WritePacket`. Allow `2 × transport.MaxControlHold` in probe timeouts. Don't probe a link that carried data recently (data is proof of life). Jitter the probe interval rather than a fixed 2 s. Consider probing warm backups less often than the active path. The path layer itself never pads.

**For TP-028 (tls):** declare `transport.ShapingSupport` and refuse the rest. Record-level padding inside TLS (or frame padding inside the stream, as udp does) honours `Padding`; batching maps naturally onto coalescing frames into records. Run `transporttest.Run` with `Shaping` set and `Refused`. `ControlWriter` is the place to fold probes into records. Bucket sizes are record sizes.

**For TP-024 / TP-026 (censor lab):** `lab/shaping_test.go` is the capture pattern (sender: `udp.TestLabSendShaped` run in a node with `-lab-target`). The matrix should add shaped rows per transport (e.g. udp+buckets), report `SendStats.Overhead` next to pass/fail, and judge: packet-size profiling (distinct sizes, WireGuard's 148/92 handshake sizes), rhythm (keepalives, the path layer's probes, rekeys every 2 min), which padding alone doesn't hide. Defaults stay "no shaping" until the lab picks values.

**For devmap (TP-004, merged):** its spec can't express shaping yet; adding it is a `shaping:` key per endpoint/inbound encoded with `Shaping.Marshal`, checked in `plan.go` with `ParseShaping` before `CheckEndpoint`/`CheckInbound`.

## Review findings
Review verdict: merge after these (orchestrator decisions).
- [ ] 1. netmap Build rejects undecodable shaping; fixtures use real `Shaping.Marshal()` output (layering: say where the shared validation lives)
- [ ] 2. Rollout policy in DESIGN ("Transports own traffic shape") and here: the controller emits shaping only to nodes that report supporting it, from the agent version/capabilities reported at registration; notes for TP-034/TP-038/TP-044; log that not raising min_reader is OK only because nothing is deployed
- [ ] 3. Contract: RTT samples via WriteControl are upper bounds: the transport reports the hold, or latency is measured on unheld traffic; WireGuard handshakes and data never go through WriteControl; note for TP-031
- [ ] 4. memory adapter: opt-in `AcceptShaping` (reports support, Overhead 0) so shaped maps are testable in-process; note for TP-006/TP-008
- [ ] 5. Listener-level cover tests: cover before data opens no link and queues nothing; old-counter / non-current-sender cover doesn't move RemoteAddr; `Counters.Cover` counts it
- [ ] N1. `Marshal` validates
- [ ] N2. Distinct close reason for a link whose new shaping is refused (not ErrRevoked)
- [ ] N3. Router's "delivered" vs `Counters.Delivered` naming consistent
- [ ] N4. Positive control in the conformance case where the listener refuses a peer link
- [ ] N5. Lab test asserts exactly 261 datagrams per port
- [ ] N6. Padding appends zeros without a per-send allocation
- [ ] N7. Optional `interface{ Sent() SendStats }` for the engine
- [ ] N8. Fix the "sizes, not secrets" comment

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-027, branch: tp-027-transport-shaping
- 2026-10-10 the map carries shaping in a new `shaping` field next to `settings` (not inside `InboundLink.settings` as TP-003's note said); netmap.proto comment and DESIGN.md "Transports own traffic shape" updated
- 2026-10-10 in-progress → review
- 2026-10-10 review → has-errors — review: 5 findings, 8 nits (see Review findings)
- 2026-10-10 has-errors → in-progress — owner: agent-tp-027, picking up the review findings
