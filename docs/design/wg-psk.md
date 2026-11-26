# thinkpol-vpn — A WireGuard preshared key per peer pair

A design note: every pair of WireGuard peers gets a preshared key (PSK) from the map, so a flow recorded now stays unreadable after Curve25519 falls, whatever transport carried it. Proposed 2026-11-26, revised after review the same day, **awaiting the owner's approval**: no ticket is filed and nothing is built until then. It ships in M2 with the classical `reality` hello (owner, 2026-11-26; the reality-hello note's RR68 and its open question 5). The entry point is [DESIGN.md](../../DESIGN.md); WireGuard is [`wg`](../../internal/dataplane/wg/doc.go); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## What it protects

**Against a passive recorder who breaks Curve25519 later.** WireGuard's handshake is Noise IKpsk2: the PSK enters the key schedule after both Diffie-Hellman steps, so recovering every X25519 secret of a recorded handshake still leaves a 256-bit symmetric key. That holds under any outer layer: a classical `reality` hello, `udp`'s seal, a relay.

**Not against an active attacker after the break.** The map's Ed25519 signature falls too, and HPKE's base mode doesn't authenticate the sender, so a forged map can hand a node the attacker's PSKs and keys. The map signature stays the classical anchor of everything in it, PSKs included (RR92 (5)).

**Not protected either:** metadata (who talked to whom, sizes, timing: WireGuard's identity hiding is classical); the outer layer and what travels outside WireGuard; a key taken from an end ("Seizure" below).

## Where the key comes from

- **(a) Derived from a secret both ends hold: rejected.** A WireGuard pair joins two end points across relays ([overlay](overlay.md)); a device and its exit share no link secret. `udp`'s link secret is per hop and held by the relay (RR33); `reality`'s short id is 64 bits and its listener key classical and shared (RR64).
- **(b) A fresh 32-byte random key per pair, written by the map builder into both peers' sections: chosen for M2.** Only the two ends and the builder know it. All-zero means "no PSK" to WireGuard and is refused.
- **(c) A post-quantum exchange in band** (Rosenpass-style): a protocol of its own with no Go implementation to take ([security](security.md#rules), rule 4). Later, if ever.

## The map's post-quantum seal

Sections are sealed to each node's X25519 map key, and envelopes are public: taken from anyone, gossiped, copied by hand before the controller, archivable by anyone (RR45). So the PSKs get a seal of their own.

- **Each node gets an X-Wing map key** (ML-KEM-768 + X25519, `hpke.MLKEM768X25519()` in go1.26.11's `crypto/hpke`): a 32-byte seed, a 1,216-byte public key.
- **A section gains one field, `pq_sealed`**: a key period (4 bytes) and one HPKE seal (`hpke.HKDFSHA256()`, `hpke.ChaCha20Poly1305()`) of the list `{peer id, PSK}`. It sits inside the classical section, so the period links no section to a node in the envelope. In M2 only the PSKs move there (open question 2). No format bump: sections keep one padded length.
- **Binding.** `hpke.Seal` takes no associated data; its `info` enters the key schedule. One-shot `hpke.Seal`/`hpke.Open`, with `info` = `"thinkpol wg-psk v1"`, a zero byte, then fixed-width: space id, key epoch, map version, the section owner's node id, the key period. The node builds `info` from the header and its own id, so a seal moved to another space, version, node or period doesn't open; `info` is never sent. Each build encapsulates afresh per section.
- **The reader** refuses the field if it doesn't open, or names a peer twice or a peer not in `Section.peers`. A peer with no entry stays keyless and falls under the per-peer rule below.

### Rotating the X-Wing key

A seed that never changes, once seized, opens every archived blob sealed to it. So the key moves forward with every build, along a one-way chain:

- **The chain:** `seed(p+1) = HKDF-SHA256(seed(p), "thinkpol x-wing next")`; any 32 bytes is a valid X-Wing seed. The period `p` counts builds.
- **The builder** (`devmap`) keeps each node's current seed in a state file, advances it per build, seals to its public key and overwrites the file by atomic rename, destroying the old seed. The new public key never travels: the builder derives it.
- **The node** keeps one seed, `pq.key`, beside `node.key`. A section sealed at period `q > p` makes it hash forward (at most 10,000 steps), open, store the map, then replace `pq.key` with `seed(q)`. A crash between the two leaves an older seed and a newer map, and the next start hashes forward again. No grace period: a node only ever opens its newest map. A period behind its own (a builder restored from an old copy) is refused and reported: re-key by hand.
- **Cost:** a hash and a file rewrite per node per build; 4 bytes per section; no new flag day or channel. The builder holds every node's current seed, as it already writes every PSK.
- **Bound:** a seized seed opens blobs from the node's last taken map on, never earlier ones.
- **The controller (M4)** makes no node keys: each node generates its next X-Wing key with each PSK rotation, reports the public half over its control channel (signed with its Ed25519 key: classical, like the map), and deletes the old seed once it has a map sealed to the new one.

## Per peer, not per link

**WireGuard holds one PSK per peer, and thinkpol has one WireGuard peer per remote node,** keyed by its public key, its endpoint the node id; paths, first hops and transports sit beneath it (`wg.Device.Configure`, `path.Bind`). So:

- **One key per pair**, the same bytes in both sections, covering every hop; failover or a new transport never touch it.
- **A key change updates the peer in place** (`update_only`, `preshared_key`). Today `Configure` skips a peer whose node and allowed IPs are unchanged; a remove and re-add would drop the session the rotation relies on.

## Rotation and rollout

**A rotation is a flag day per pair, softened by the live session.** WireGuard's IPC replaces only the handshake's PSK and keeps the current keypair (`uapi.go`). In IKpsk2 the responder answers without checking the PSK. So a mismatched initiation fails at the initiator, which retries every 5 s (`RekeyTimeout`). It also costs the responder its `previous` keypair (`BeginSymmetricSession`), so packets in flight on it are lost; `current` stays.

A keypair carries data until 180 s after its handshake (`RejectAfterTime`). When its initiator sends, it rekeys from 120 s, leaving 60 s. When only its responder sends, the initiator rekeys on receipt from 165 s, leaving about 15 s. So:

- **No outage when the second end applies within about 15 s** of the first (60 s if the keypair's initiator sends). Beyond that, the outage is the skew less the keypair's remaining life, plus up to about 5.3 s. A few in-flight packets may drop even inside the window. An idle pair handshakes afresh on its first traffic.
- **No grace inside WireGuard:** one PSK slot, no "try the old one".
- **`devmap`:** PSKs are fresh on every build, like link secrets, which already make each build a flag day for every link. The lab's seeded secrets derive PSKs and X-Wing seeds.
- **The controller (M4):** PSKs persist across publishes and rotate per pair, staggered (open question 4). Map delivery never depends on the pair's own session: it comes by link gossip.

**Rollout: refuse, never weaken** ([transports](transports.md)).

- **An old binary ignores `pq_sealed`** and sets no PSK: its next handshake with a keyed peer fails, so the pair goes dead rather than keyless. A keypair derived before, with a zero PSK, still carries data for up to 180 s. The capability gate keeps that mixed pair from arising. Raising `SectionReader` would also freeze the node on its last map, revocations included, so it stays 1.
- **The gate:** the controller keys a pair once both ends report the capability; `devmap` once the spec's switch `wireguard_psk` is on (off in the first release; the owner turns it on after updating every node).
- **A new binary that can't open `pq_sealed`** leaves those peers out and reports it, never configuring them keyless. `Build` checks every seal opens.

**`chrome-classical` per peer.** A link's hello is per link, and the path layer picks each peer's first hop from that peer's candidates. So a keyless peer's candidates drop every first hop whose link dials `chrome-classical`; with none left, that peer has no path and says why. Other peers and the link carry on. The node sees only its first hop, so the builder refuses any path with a classical link for a keyless pair. `devmap` with the switch off, where every pair is keyless, refuses `chrome-classical` outright.

## Health under a PSK mismatch

`wg` clears a pending handshake on "Sending handshake response" (`doc.go`), which wireguard-go logs whatever the PSK:

- **(a) During a rotation,** the re-initiating end is graded unanswered after `ExitHandshakeDeadline` (15 s) while the old keypair still carries data.
- **(b) After the skew outlasts the keypair,** an end that answers the peer's initiations clears its own pending one: health says OK on a dead link.

**The fix: clear only on a confirmed keypair.**

- **Clearing.** Pending clears on "Received handshake response", logged only once the initiator opened the response (which needs the PSK), or when `LastHandshake` passes the pending initiation. wireguard-go moves `last_handshake_time` on the responder only in `ReceivedWithKeypair`, on the first packet over the new keypair, and the initiator sends a keepalive as soon as it opens the response: a real completion shows within a round trip. `Status` already reads `LastHandshake`. "Sending handshake response" clears nothing; crossing initiations (`TestAPeersInitiationClearsAPendingOne`) still clear through that keepalive.
- **A `rekeying` grade for (a).** `rx_bytes` counts the peer's handshake messages too, so it can't show the old keypair works. Instead `path.Bind` records per peer when it last delivered a transport-data message (WireGuard type 4). A pending peer whose last handshake is under 180 s old and that delivered data since its first unanswered initiation is `rekeying`: a warning naming when the keypair expires. At expiry, or 15 s after data stops, it is unanswered as today. A relay forging type-4 messages could delay the alarm, never past the 180 s.

## Seizure and revocation (TP-169)

A seized node holds its own pairs' PSKs and its current X-Wing seed; relays hold no PSK of the pairs they carry. Revoking it removes its pairs, and no other pair needs a new key. With a future break it opens its pairs' recorded payload since the map it last took (`devmap`: that build; the controller: each pair's last rotation), and its `pq_sealed` blobs from its current period on. A covert copy also follows the chain forward until the owner re-keys the node, as a copied `node.key` already allows. A node's WireGuard key rotation re-adds its peers, so their PSKs change in the same map.

## Keys on nodes and builders

- **New files only.** Key files are create-only (`devmap/keys.go`), and `node.key`'s reader refuses unknown fields, so `node.key` and `<name>.pub` don't change. `thinkpol dev keygen pq <node>...` creates, for nodes that lack them, the first seed (copied to the node once, as `pq.key`) and the builder's chain file. No public-key file is needed: the builder derives it. Both files are state rewritten by atomic rename, not identity keys.
- **On the node,** `pq.key` sits with the private keys in the root-only state directory ([security](security.md#node-safety)); PSKs live in the sealed map file and wireguard-go's memory. The local API and `diag` never show one; `dev map describe` shows a fingerprint. **TP-170** moves `pq.key` into the OS keystore with the other device keys.
- **The controller (M4)** keeps its PSK table in the live database only, **never in a backup**: backups are encrypted to the Ed25519 recovery key ([control plane](control-plane.md#the-signed-map)), readable once Curve25519 falls. A restore regenerates every PSK, one flag day per pair on a rare event. Open question 3 would remove the table.

## Shared nodes and grants (M4)

A guest's builder must seal a shared node's `pq_sealed` to that node's X-Wing key, which the grant token ([control plane](control-plane.md#joining)) doesn't carry. Grants are M4, and M4 must follow this rule: the node keeps **one X-Wing key per space it serves**; the grant carries its public half, signed by the owner space; the node reports each rotation to the guest's controller the same way. Until a guest's sections carry `pq_sealed`, the node treats that guest's pairs as keyless.

## Cost

- **CPU: none per handshake** (IKpsk2 always runs the PSK step, with zeros when unset). Taking a map: one X-Wing decapsulation, well under 1 ms.
- **Wire: 0 bytes.**
- **Map:** 1,140 bytes per section with peers (1,120-byte encapsulation, tag, period) plus about 44 per peer: about 2 KB for an exit with the PRD's 20 devices. It must still fit the 8 KiB section bucket (`TestSectionLengthHidesRole`); if not, every space moves to 16 KiB, doubling the smallest envelope to 128 KiB.

## M2 work

Six tickets, 1 S and 5 M. Estimates here have run about 2x optimistic, so plan it as an L epic.

| Ticket | Size |
|---|---|
| `wg`: PSK per peer, updated in place; stock-wireguard-go conformance | S |
| Health: clearing on a confirmed keypair, the Bind's data timestamp, `rekeying` | M |
| `netmap`: `pq_sealed`, the seal and `info`, the reader's and `Build`'s checks, the size test | M |
| Node: `pq.key`, the forward chain and its crash order, refusals, the per-peer `chrome-classical` filter | M |
| `devmap`: PSKs per pair, chain files and `dev keygen pq`, the switch, the whole-path check | M |
| Lab: the matrix with the switch on, a wrong PSK, the rotation gap | M |

## Tests

- **Unit.** `netmap`: a pair's sections carry the same PSK; a seal moved to another section, version, space or period doesn't open; two builds encapsulate differently; unknown or duplicated peer ids, a short, all-zero or orphan PSK are refused; the chain gives the same seed after one or five missed builds; a period behind is refused. `devmap`: relays get no key; seeded builds repeat; the switch off writes none and refuses `chrome-classical`. Node: a crash between the map and seed writes recovers; a keyless peer loses its classical candidates while a keyed one keeps them.
- **`wg`, two real wireguard-go devices.** Equal PSKs pass traffic, different ones never complete, an in-place change keeps the session. **Mismatch:** both ends send, so each answers the other's initiations; neither clears its pending one, and health says unanswered within 15 s. **Rotation:** a busy pair mid-rotation is `rekeying` while its keypair lives, and unanswered within 15 s of its expiry.
- **Lab.** A device → entry (`reality`) → exit chain passes traffic PSK'd, and every matrix row runs with the switch on; a wrong PSK never links, and health says unanswered. **The rotation gap**, on real timers: a flow both ways and a flow only from the keypair's responder to its initiator, a packet every 100 ms; the second end takes its map 0, 10, 30, 90 and 240 s after the first, each skew on its own pair, concurrently. The oracle is the longest gap: at most max(0, skew − remaining life) + 5.3 s, the remaining life computed from the measured `LastHandshake`. It doesn't count loss, since packets on `previous` may drop. Its own `make lab-gotest` (about 7 minutes), outside the full lab.
- **Conformance.** A stock wireguard-go device configured by UAPI text with the same PSK handshakes with thinkpol's.

## Residual risks

- **RR68 (2) narrows** (the reality-hello note's row): a recorded flow's payload behind a classical link no longer becomes readable once Curve25519 falls.
- **New row, RR92** (Devices and the map): *What a future quantum break still opens.* **When:** once Curve25519 falls, to whoever recorded flows or kept an envelope or backup. **What leaks:** (1) who talked to whom, sizes, timing; (2) a section's other secrets (link secrets, short ids, the `reality` listener key, endpoints, rules) from a kept envelope; (3) with a seized end, its pairs' payload since the map it last took and its `pq_sealed` blobs from its current period on (forward until re-keyed, if covert); (4) the builder holds every current PSK and X-Wing seed; the M4 controller's backups must hold none, being encrypted to the Ed25519 recovery key; (5) an active attacker forges the map (Ed25519) and installs its own PSKs. **Breaks:** none until open question 5. **Accepted:** payload against a passive recorder is what's protected; (2) waits for question 2, (5) for a post-quantum map signature.

## Open questions for the owner

1. **An X-Wing key per node, moved forward every build, in M2?** Without it a kept envelope yields every PSK; a fixed key saves the chain files but lets a seized seed open every PSK the node ever held. *Recommended: yes, with the chain.*
2. **Only the PSKs under the X-Wing seal, or every secret of a section?** *Recommended: the PSKs in M2, the whole section at the next map format.*
3. **For the M4 controller, a static X-Wing exchange instead of a PSK table?** One end encapsulates to the other's X-Wing key and reports the ciphertext; the builder places only that, so the controller never holds a PSK. It costs a round trip per rotation. *Recommended: design it with the controller; keep (b) for M2.*
4. **The controller's rotation period.** Shorter bounds what a seized PSK opens; each rotation is a flag day for a node offline at the time. *Recommended: 30 days per pair, staggered, plus on node-key rotation and on demand.*
5. **A PRD requirement** ("traffic recorded now stays confidential after a break of Curve25519: payload, against a passive recorder"), a should for M2, for RR68 and RR92 to name? *Recommended: yes.*
