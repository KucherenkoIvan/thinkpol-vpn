# thinkpol-vpn — A WireGuard preshared key per peer pair

A design note: every pair of WireGuard peers gets a preshared key (PSK) from the map, so a flow recorded now stays unreadable after Curve25519 falls, whatever transport carried it. Proposed 2026-11-26, **awaiting the owner's approval**: no ticket is filed and nothing is built until then. Built with the classical `reality` hello, in M2 (owner, 2026-11-26; the reality-hello note's RR68 and its open question 5). The entry point is [DESIGN.md](../../DESIGN.md); WireGuard is [`wg`](../../internal/dataplane/wg/doc.go); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## What it protects

**Against an adversary who records now and breaks Curve25519 later.** WireGuard's handshake is Noise IKpsk2: the PSK enters the key schedule after both Diffie-Hellman steps, so recovering every X25519 secret of a recorded handshake still leaves a 256-bit symmetric key (128 bits of work under Grover). That holds under any outer layer: a classical `reality` hello, `udp`'s seal, a relay. After the break, an active attacker can't complete a handshake without the PSK either.

**Not protected:** metadata (WireGuard's identity hiding is classical, so a recorded handshake shows which device and which exit talked; sizes and timing were never hidden); the outer layer itself and what travels outside WireGuard (transport probes and frames, no payload); a key stolen from an end ("Seizure" below); and the map, unless its PSKs are sealed post-quantum (next).

## Where the key comes from

**(a) Derived from a secret both ends hold: rejected.** A transport link joins two adjacent nodes; a WireGuard pair joins two end points across relays ([overlay](overlay.md)). A device and its exit share no link secret, and the entry between them holds the device's. `udp`'s link secret is 32 random bytes (`udp.MinSecretSize`), sound as HKDF input, but per hop, held by the relay and by whoever opens either end's section (RR33). `reality`'s short id is 8 bytes: 64 bits, 32 under Grover. Its listener key is classical and shared by every device on it (RR64).

**(b) A fresh 32-byte random key per pair, written by the map builder into both peers' sections: recommended.** Only the two ends and the builder (which holds every credential already) know it; relays, other spaces and other nodes never do. All-zero means "no PSK" to WireGuard and is refused.

**(c) A post-quantum exchange in band** (Rosenpass-style: an ML-KEM handshake beside WireGuard replacing the PSK every 2 minutes) adds forward secrecy and keeps the secret out of the map, but it is a protocol of its own with no Go implementation to take ([security](security.md#rules), rule 4). Later, if ever.

**The map's seal decides whether (b) protects anything.** Sections are sealed to each node's X25519 map key, envelopes are taken from anyone and meant to spread by gossip ([control plane](control-plane.md#the-signed-map)), and before the controller they are copied by hand through channels a censor may record. Every holder keeps every section (RR45). So an envelope is public, and a PSK in a classical section is readable once Curve25519 falls. Hence:

- **Each node gets a post-quantum map key**, X-Wing (ML-KEM-768 + X25519, `hpke.MLKEM768X25519` in Go 1.26's `crypto/hpke`, the toolchain in use): a 32-byte private seed, a 1,216-byte public key.
- **A section gains one field, `pq_sealed`**: an HPKE seal (X-Wing, HKDF-SHA256, ChaCha20-Poly1305) to that key of `{peer id, PSK}` per peer, its associated data binding space id, key epoch and version as sections do. In M2 only the PSKs move there (open question 2). No format bump: sections keep one padded length, and the X25519 half keeps it at least as strong as today's seal.

## Per peer, not per link

**WireGuard holds one PSK per peer, and thinkpol has one WireGuard peer per remote node:** each `Section.peers` entry is one peer on one device (the overlay device or that exit's), keyed by its public key, its endpoint the node id; every path, first hop and transport sits beneath it in the path layer (`wg.Device.Configure`, `path.Bind`). That forces:

- **One key per pair**, the same bytes in both sections. Failover, a new first hop or another transport never touch it, and one end-to-end key covers every hop: a device ↔ exit flow is PSK'd on the classical device → entry link and the `udp` entry → exit link alike.
- **A key change updates the peer in place** (`update_only`, `preshared_key`). Today `Configure` skips a peer whose node and allowed IPs are unchanged; a remove and re-add would drop the live session the rotation relies on.

## Rotation and rollout

**A rotation is a flag day per pair, softened by the live session.** WireGuard's IPC sets only the handshake's PSK and keeps the current session (`uapi.go`). A mismatched handshake fails at the initiator, which can't open the response; the responder keeps its current session. A session carries data until 180 s after its handshake (`RejectAfterTime`) and re-handshakes from 120 s (`RekeyAfterTime`), so a busy pair's session has 60–180 s left when the first end applies:

- **No outage when both ends apply within 60 s** (up to 180 s, by the session's age). Beyond that the outage is the skew less the session's remaining life, plus at most 5.3 s (`RekeyTimeout` and its jitter) to the next initiation. An idle pair has no session; its first traffic after both apply handshakes at once.
- **No grace period exists inside WireGuard:** one PSK slot, no "try the old one". The session overlap is the grace.
- **`devmap`:** PSKs are fresh on every build, like the link secrets, which already make each build a flag day for every link: the skew is the owner's copying, and the PSK adds no new one. The lab's seeded secrets derive PSKs too.
- **The controller:** PSKs stay across publishes and rotate per pair every 30 days, staggered (open question 3). A node that misses a rotation can't reach that peer until it has the new map, so map delivery must never depend on that pair's WireGuard session: it comes by the link's own gossip, whose credentials didn't change (a requirement on M4's push).

**Rollout: refuse, never weaken** ([transports](transports.md)).
- **An old binary ignores `pq_sealed`** and sets no PSK while the other end has one: its handshakes fail, **a dead link, not a silent downgrade**. Raising `SectionReader` would kill the link too and also freeze the node on its last map, revocations included, so it stays 1.
- **A downgrade needs both ends keyless,** which only the builder can cause, so it sets a pair's PSK only once both ends report the capability (the controller), or, under `devmap`, once the spec's switch `wireguard_psk` is on: off in its first release, turned on by the owner after updating every node.
- **`chrome-classical` requires it:** `devmap` refuses a classical hello with the switch off, and a node refuses a `chrome-classical` endpoint while any peer in its section lacks a PSK.
- **A new binary that can't open `pq_sealed`** leaves those peers out and reports it, never configuring them keyless; `Build` checks every seal opens before publishing.

**Seizure and revocation (TP-169).** A seized node holds its own pairs' PSKs and nobody else's: relays hold none of the pairs they carry. Revoking it removes its pairs; no other pair needs a new key. With its PSKs and a future break, its pairs' recorded traffic since the last rotation is readable: since the last build under `devmap`, at most 30 days with the controller. A node's WireGuard key rotation re-adds its peers anyway, so their PSKs change in the same map, with no extra flag day.

## Storage on devices

**Nothing new is stored.** PSKs live in the node's map file, sealed to its X-Wing key, which sits with the other private keys in the root-only state directory ([security](security.md#node-safety)), and in memory in wireguard-go's handshake state. The local API and `diag` never show one; `dev map describe` shows a fingerprint, as for credentials. **TP-170** moves a device's private keys into the OS keystore; the X-Wing seed goes with them, and then a disk copy alone yields neither keys nor PSKs.

## Cost

- **CPU: none per handshake.** WireGuard always runs IKpsk2's PSK step, with 32 zero bytes when none is set. Taking a map costs one X-Wing decapsulation (well under 1 ms); building one, an encapsulation per section.
- **Wire: 0 bytes.** Handshake messages stay 148 and 92 bytes.
- **Map:** 1,136 bytes per section with peers (the 1,120-byte encapsulation, a 16-byte tag) and about 44 per peer (32-byte key, 8-byte id, framing): about 2 KB more for an exit with the PRD's 20 devices. The PRD scale must still fit the 8 KiB section bucket (`TestSectionLengthHidesRole`); if not, every space moves to 16 KiB, doubling the smallest envelope from 64 to 128 KiB.
- **Keys:** one more per node, in a new key file (key files are never replaced); 1,216 more bytes in its public file.
- **Builder:** a key per pair into two sections, the capability gate, the `chrome-classical` refusal.

## Tests

- **Unit.** `netmap`: both sections of a pair carry the same PSK; another node's key doesn't open a seal; `Build` refuses a PSK not 32 bytes, all zero, or for a peer the section lacks. `devmap`: relays on a path get no key; seeded builds repeat it; the switch off writes none. `wg`: two real wireguard-go devices pass traffic with equal PSKs, never complete a handshake with different ones, and keep their session across an in-place change. Engine: `chrome-classical` with a keyless peer is refused.
- **Lab.** A device → entry (`reality`) → exit chain passes traffic PSK'd, and every matrix row runs with the switch on. A wrong PSK never links; health reports the exit's handshake unanswered within `ExitHandshakeDeadline` (15 s). **The rotation gap**: a packet every 100 ms over a busy pair, the second end taking the new map 0, 30, 90 and 240 s after the first; expected loss 0 for the first two, at most the skew less the session's remaining life plus 5.3 s for the others. It runs on WireGuard's real timers (about 6 minutes), so it is its own `make lab-gotest`, outside the full lab.
- **Conformance.** A stock wireguard-go device configured by plain UAPI text with the same PSK handshakes with thinkpol's: the map's bytes are WireGuard's PSK unaltered.

## Residual risks

- **RR68 (2) narrows** (proposed by the reality-hello note): with every pair behind a classical link PSK'd, a recorded flow's payload no longer becomes readable once Curve25519 falls; what remains is the new row.
- **New row, RR69** (Devices and the map): *What a future quantum break still opens.* When: once Curve25519 falls, to whoever recorded flows or kept an envelope. What leaks: (1) who talked to whom, sizes, timing; (2) a section's other secrets (link secrets, short ids, the `reality` listener key, endpoints, rules) from a kept envelope; (3) with a seized end's PSKs, its pairs' payload since the last rotation; (4) the builder holds every PSK. Breaks: none until open question 4. Accepted: payload is what's protected; (2) waits for question 2, (3) is bounded by rotation.

## Open questions for the owner

1. **Seal the PSKs post-quantum, with an X-Wing key per node?** A plain PSK in today's X25519 section saves a key and about 1.1 KB per section, but a kept envelope and a future break yield every PSK. *Recommended: seal them.*
2. **Only the PSKs in that seal, or every secret of a section?** Moving `udp`'s link secrets too would make its outer seal post-quantum (it is symmetric; only its delivery is classical). *Recommended: the PSKs in M2, the whole section with X-Wing at the next map format.*
3. **The controller's rotation period.** Shorter bounds what a seized PSK opens; each rotation strands an offline node until its map arrives. *Recommended: 30 days per pair, staggered, plus on node-key rotation and on demand.*
4. **A PRD requirement** ("traffic recorded now stays confidential after a break of Curve25519: payload, not metadata"), a should for M2, for RR68 and RR69 to name? *Recommended: yes.*
