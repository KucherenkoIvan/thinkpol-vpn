# thinkpol-vpn — A WireGuard preshared key per peer pair

A design note: every pair of WireGuard peers gets a preshared key (PSK) from the map, so a flow recorded now stays unreadable after Curve25519 falls. Proposed 2026-11-26, revised after two reviews, **awaiting the owner's approval**: no ticket is filed and nothing is built until then. It ships in M2 with the classical `reality` hello (owner, 2026-11-26; the reality-hello note's RR68 and its open question 5), in one of two cuts (open question 1). The entry point is [DESIGN.md](../../DESIGN.md); WireGuard is [`wg`](../../internal/dataplane/wg/doc.go); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## What it protects

**Against a passive recorder who breaks Curve25519 later.** In WireGuard's Noise IKpsk2 the PSK enters the key schedule after both Diffie-Hellman steps, so every X25519 secret of a recorded handshake still leaves a 256-bit symmetric key, under any outer layer.

**Not against an active attacker after the break.** The map's Ed25519 signature falls too, so a forged map can hand a node the attacker's PSKs (RR92 (5)).

**Not protected either:** metadata (who talked to whom, sizes, timing); the outer layer and what travels outside WireGuard; a key taken from an end ("Seizure" below).

## Where the key comes from

- **(a) Derived from a secret both ends hold: rejected.** A WireGuard pair spans relays ([overlay](overlay.md)): link secrets are per hop and held by relays (RR33); `reality`'s are short or classical (RR64).
- **(b) A fresh 32-byte random key per pair, written by the map builder into both peers' sections: chosen.** Only the two ends and the builder know it. All-zero means "no PSK" to WireGuard and is refused.
- **(c) A post-quantum exchange in band** (Rosenpass-style): no Go implementation to take ([security](security.md#rules), rule 4). Later, if ever.

## Two cuts for M2

Both keep the goal: a passive recorder learns no payload, and no link trades post-quantum protection for reach. They differ in what a seized node's key opens from an archive of envelopes, which are public (RR45).

| | **M2-small** | **M2-full** |
|---|---|---|
| Builds | PSK per pair; a **static** X-Wing key per node; the per-peer `chrome-classical` refusal; the confirmed-keypair health fix; `dev keygen pq -rekey` | M2-small, plus the per-build X-Wing chain, the `rekeying` grade, the rotation-gap lab |
| A seized node's seed opens | every `pq_sealed` blob sealed to it since the key was made or last re-keyed: every PSK its pairs ever had in that time, so their recorded payload | its blobs from the map it last took on, forward until re-keyed |
| A copy of the builder's files opens | nothing: the builder keeps only public keys | every node's blobs from the copy's period on, until each node is re-keyed |
| Tickets | 2 S, 4 M | 2 S, 8 M |

Estimates here have run about 2× over: plan M2-small as an L epic, M2-full as about two. The chain serves the seizure-archive bound; `devmap` builds are flag days, so smooth rotation pays off only with M4's staggered rotation, where nodes make their own keys anyway. M2-small defers the chain, the `rekeying` grade and the rotation-gap lab to M4.

## The map's post-quantum seal

Sections are sealed to each node's X25519 map key, and envelopes are public and archivable by anyone, so the PSKs get a seal of their own.

- **Each node gets an X-Wing map key** (ML-KEM-768 + X25519, `hpke.MLKEM768X25519()` in go1.26.11's `crypto/hpke`): a 32-byte seed, a 1,216-byte public key.
- **A section gains one field, `pq_sealed`**: one HPKE seal (`hpke.HKDFSHA256()`, `hpke.ChaCha20Poly1305()`) of the list `{peer id, PSK}`, inside the classical section. In M2 only the PSKs move there (open question 2). No format bump: sections keep one padded length.
- **Binding.** One-shot `hpke.Seal`/`hpke.Open` (no associated data; `info` enters the key schedule), `info` = `"thinkpol wg-psk v1"`, a zero byte, then fixed-width: space id, key epoch, map version, the section owner's node id. The node builds `info` from the header and its own id, so a moved seal doesn't open; `info` is never sent. Each build encapsulates afresh.
- **The reader** refuses the field if it doesn't open or names a peer twice or one not in `Section.peers`. A peer with no entry stays keyless (the per-peer rule below).

## Keys on nodes and builders

- **New files only.** Key files are create-only (`devmap/keys.go`, `O_EXCL`) and `node.key`'s reader refuses unknown fields, so existing files don't change.
- **`thinkpol dev keygen pq <node>...`** creates, for nodes that lack them, `<name>.pq.key` (the seed, copied to the node once as `pq.key`, then deleted from the builder: a kept copy is a seized seed) and the builder's half: `<name>.pq.pub` in M2-small, the chain entry in M2-full.
- **`thinkpol dev keygen pq -rekey <node>...`** replaces both with a **fresh random seed**, never a hash of the old one, by atomic rename. The node gets the new `pq.key` by hand, as node keys are today, with the next map. A node that takes that map first leaves its keyed peers out, and says so, until the file arrives; it rereads `pq.key` when the file changes.
- **On the node,** `pq.key` sits with the private keys in the root-only state directory ([security](security.md#node-safety)); PSKs live in the sealed map file and wireguard-go's memory, never in the local API or `diag`. **TP-170** moves `pq.key` into the OS keystore.

## Rotating the X-Wing key (M2-full; M4 under M2-small)

The chain moves each seed forward with every map:

- **The chain:** `seed(v) = hkdf.Expand(sha256.New, seed(v−1), "thinkpol x-wing next v1", 32)` (Go's `crypto/hkdf`: the old seed is the pseudorandom key, the label is `info`, the output 32 bytes).
- **The period is the map version,** which only goes up, across key epochs too; `info` already binds it.
- **The builder** keeps each node's `(version, seed)` in a chain file. To build version `v` it refuses `v` at or below the file's version, hashes forward (at most 10,000 steps, or re-key), and renames the file to `seed(v)` **before** it writes the map, so no version is published under two seeds. A builder that is only behind (restored from a copy) needs no re-key: the chain is deterministic, and `dev map rotate` takes a version past the deployed map, so it hashes forward to the same seeds.
- **The chain file stays out of backups and sync.** It lives in its own directory (`-pq-state`, default the user's state directory), which the builder refuses inside the backed-up key directory and marks excluded from Time Machine (the sticky extended attribute `tmutil addexclusion` sets; no root needed). The runbook says to exclude it from every other backup and sync tool. Filesystem snapshots ignore exclusions: RR92 (4) holds only while no copy or snapshot of the file survives.
- **The node** keeps `(version, seed)` in `pq.key`. For a section of version `q > p` it hashes forward, opens, stores the map durably (fsync the file and its directory), and only then replaces `pq.key` with `seed(q)` the same way. A crash in between leaves an older seed beside a newer map, which hashes forward again; never the reverse.
- **The controller (M4)** makes no node keys: each node generates a fresh X-Wing key with each PSK rotation, reports the public half (signed with its Ed25519 key: classical, like the map), and deletes the old seed only once every space it serves has sealed to the new one.

## Per peer, not per link

**WireGuard holds one PSK per peer, and thinkpol has one WireGuard peer per remote node;** paths, first hops and transports sit beneath it (`wg.Device.Configure`, `path.Bind`). So one key per pair covers every hop, and failover never touches it. **A key change updates the peer in place** (`update_only`, `preshared_key`): today `Configure` skips an unchanged peer, and a remove and re-add would drop the session the rotation relies on.

## Rotation and rollout

**A PSK change is a flag day per pair, softened by the live session.** WireGuard's IPC keeps the current keypair (`uapi.go`). The IKpsk2 responder answers without checking the PSK, so a mismatched initiation fails at the initiator, which retries every 5 s, and costs the responder its `previous` keypair.

A keypair carries data until 180 s after its handshake (`RejectAfterTime`); its initiator rekeys from 120 s when it sends (60 s left), from 165 s when only the responder sends (about 15 s left). So no outage when the second end applies within that margin; beyond it, the outage is the skew less the keypair's remaining life, plus up to about 5.3 s.

`devmap` makes PSKs fresh on every build, like link secrets, which already make each build a flag day; the lab's seeded secrets derive PSKs and seeds. The M4 controller rotates them per pair, staggered (open question 4).

**Rollout: refuse, never weaken** ([transports](transports.md)).

- **An old binary ignores `pq_sealed`**, so its pair with a keyed peer goes dead rather than keyless. `SectionReader` stays 1: raising it would freeze the node on its last map, revocations included.
- **The gate:** the controller keys a pair once both ends report the capability; `devmap` once the spec's switch `wireguard_psk` is on (off in the first release; the owner turns it on after updating every node).
- **A new binary that can't open `pq_sealed`** leaves those peers out and reports it, never configuring them keyless. `Build` checks every seal opens.

**`chrome-classical` per peer.** A keyless peer's candidates drop every first hop whose link dials `chrome-classical`; with none left, that peer has no path and says why, and other peers carry on. The builder refuses any path with a classical link for a keyless pair, since the node sees only its first hop; with the switch off, `devmap` refuses `chrome-classical` outright.

## Health under a PSK mismatch

`wg` clears a pending handshake on "Sending handshake response", logged whatever the PSK, so an end that answers the peer's initiations says OK on a dead link. **The fix (both cuts): clear only on a confirmed keypair.**

- **Clearing.** Pending clears on "Received handshake response", logged only once the initiator opened the response (which needs the PSK), or when `LastHandshake` changes from the value `wg` read when the initiation went pending. The responder's moves on the first packet over the new keypair, and the initiator sends a keepalive as soon as it opens the response. Comparing a change, not a wall-clock `LastHandshake` with a local pending stamp, makes a clock step harmless; where `wg` needs an age (the 180 s below), it uses the monotonic moment it saw the change.
- **A response that never leaves stays pending.** In `TestAPeersInitiationClearsAPendingOne` (`device_test.go`), `path.Bind` routes A's response to a hop that isn't dialed and drops it, so X sends no keepalive and A's `LastHandshake` stays zero. A now stays pending, which is right: no keypair works. The test changes to assert that, and a twin with a working return path asserts the keepalive clears it.
- **Known grade lag: an upload-only initiator.** It rekeys on send at 120 s, so during a rotation it is graded unanswered after `ExitHandshakeDeadline` (15 s) while its old keypair still carries data for about 45 s more. Nothing it receives could show otherwise, so the lag stays.
- **A `rekeying` grade (M2-full).** `wg` stamps a peer when wireguard-go hands thinkpol's TUN a decrypted packet from it, attributed by allowed IPs: only a type-4 message whose AEAD opened gets there, so a relay can't forge one. A pending peer whose last handshake is under 180 s old and that delivered data since its first unanswered initiation is `rekeying`, a warning naming when the keypair expires; at expiry, or 15 s after data stops, it is unanswered.

## Seizure and revocation (TP-169)

A seized node holds its pairs' PSKs and its X-Wing seed (what that opens: the table above, RR92 (3)); relays hold none. Revoking it removes its pairs; no other pair needs a new key.

## Shared nodes and grants (M4)

A guest's builder must seal to a shared node's X-Wing key, which the grant token ([control plane](control-plane.md#joining)) doesn't carry. M4's rule: the node keeps **one X-Wing key per space it serves**, its public half in the grant, signed by the owner space; it reports each rotation to that space's controller, and deletes an old seed only once every space sealing to it has moved to the new key. Until then a guest's pairs are keyless.

The controller keeps its PSK table in the live database, **never in a backup**: backups are encrypted to the Ed25519 recovery key ([control plane](control-plane.md#the-signed-map)). A restore regenerates every PSK; open question 3 would remove the table.

## Cost

- **CPU: none per handshake** (IKpsk2 always runs the PSK step). Taking a map: one X-Wing decapsulation, under 1 ms.
- **Wire: 0 bytes.**
- **Map:** 1,136 bytes per section with peers (1,120-byte encapsulation, tag) plus about 44 per peer: about 2 KB for an exit with the PRD's 20 devices. It must still fit the 8 KiB section bucket (`TestSectionLengthHidesRole`); if not, every space moves to 16 KiB, doubling the smallest envelope to 128 KiB.

## M2 work

**M2-small:**

| Ticket | Size |
|---|---|
| `wg`: PSK per peer, updated in place; stock-wireguard-go conformance | S |
| Health: clearing on a confirmed keypair, the changed test and its twin | M |
| `netmap`: `pq_sealed`, the seal and `info`, the reader's and `Build`'s checks, the size test | M |
| Node: static `pq.key`, rereading it, refusals, the per-peer `chrome-classical` filter | M |
| `devmap`: PSKs per pair, `dev keygen pq` and `-rekey`, the switch, the whole-path check | M |
| Lab: the matrix with the switch on, a wrong PSK | S |

**M2-full adds:**

| Ticket | Size |
|---|---|
| Node: the forward chain, its crash order | M |
| `devmap`: chain files, version rule, the chain directory and its exclusion | M |
| Health: the TUN data stamp, `rekeying` | M |
| Lab: the rotation gap | M |

## Tests

- **Unit.** `netmap`: a pair's sections carry the same PSK; a moved seal doesn't open; bad peer ids and short, all-zero or orphan PSKs are refused. `devmap`: relays get no key; seeded builds repeat; the switch off writes none and refuses `chrome-classical`; `-rekey` writes a seed unrelated to the old one. Node: a keyless peer loses its classical candidates; a map it can't open leaves keyed peers out until `pq.key` arrives. **M2-full:** the chain gives the same seed after missed builds and from a restored builder; a version at or below the chain file's is refused; a crash at each step of the node's write order recovers.
- **`wg`, two real wireguard-go devices.** Equal PSKs pass traffic, different ones never complete, an in-place change keeps the session. **Mismatch:** both ends send and answer each other; neither clears its pending one, and health says unanswered within 15 s. **M2-full:** a busy pair mid-rotation is `rekeying` until its keypair expires, then unanswered within 15 s.
- **Lab.** A device → entry (`reality`) → exit chain passes traffic PSK'd, every matrix row runs with the switch on, and a wrong PSK never links and reads unanswered. **M2-full, the rotation gap**, on real timers: flows both ways and responder-only; the second end takes its map 0, 10, 30, 90 and 240 s after the first, one pair per skew, concurrently; the longest gap is at most max(0, skew − remaining life) + 5.3 s. Its own `make lab-gotest` (about 7 minutes).
- **Conformance.** A stock wireguard-go device given the same PSK by UAPI text handshakes with thinkpol's.

## Residual risks

- **RR68 (2) narrows** (the reality-hello note's row): a recorded flow's payload behind a classical link no longer becomes readable once Curve25519 falls.
- **New row, RR92** (Devices and the map): *What a future quantum break still opens.* **When:** once Curve25519 falls, to whoever kept flows, envelopes or backups. **What leaks:** (1) metadata; (2) a kept envelope's other section secrets (link secrets, short ids, the `reality` listener key, endpoints, rules); (3) with a seized end, its pairs' payload under its archived `pq_sealed` blobs: M2-small, since its key was made or re-keyed; M2-full, since the map it last took; forward until re-keyed, if covert; (4) the builder sees every PSK while it builds; in M2-full it holds every node's current seed, so one copy of its chain file (a backup, a synced folder, a snapshot) opens every node's blobs from that copy's version on, until each node is re-keyed, and deleting the file erases no snapshot; the M4 controller's backups hold no PSK; (5) an active attacker forges the map (Ed25519) and installs its own PSKs. **Breaks:** none until open question 5. **Accepted:** (2) waits for question 2, (5) for a post-quantum map signature.

## Open questions for the owner

1. **M2-small or M2-full?** See the table under "Two cuts". *Recommended: M2-small, about half the work. The chain is `devmap`-only work that M4 replaces with node-made keys, and M2-small's builder holds no seed; re-key a node after any suspected seizure.*
2. **Only the PSKs under the X-Wing seal, or every secret of a section?** *Recommended: the PSKs in M2, the whole section at the next map format.*
3. **For the M4 controller, a static X-Wing exchange instead of a PSK table?** One end encapsulates to the other's X-Wing key and reports the ciphertext, so the controller never holds a PSK, at a round trip per rotation. *Recommended: design it with the controller; keep (b) for M2.*
4. **The controller's rotation period.** Shorter bounds what a seized PSK opens; each is a flag day for a node offline then. *Recommended: 30 days per pair, staggered, plus on node-key rotation and on demand.*
5. **A PRD requirement** ("traffic recorded now stays confidential after a break of Curve25519: payload, against a passive recorder"), a should for M2, for RR68 and RR92 to name? *Recommended: yes.*
