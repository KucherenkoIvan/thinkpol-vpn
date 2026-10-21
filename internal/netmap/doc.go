// Package netmap is the signed network map: the envelope, sealed per-node
// sections, signing, verification and gossip. See DESIGN.md "The signed
// map".
//
// Both planes use it: the controller builds maps, every node reads its own
// section without the controller. Pure Go, buildable for Android.
//
// The wire format is the protobuf schema in proto/thinkpol/netmap/v1; only
// this package encodes or decodes it (depguard enforces this). A map's life:
//
//   - [Build] seals each node's [Section] to that node's [NodePublicKey],
//     pads the sections to a power-of-two count of equal-length sealed boxes
//     in random order, and signs the result with the space's signing key.
//   - [Verify] checks a map against a [Trust] (the signing key, and the
//     space id and recovery key when known) and returns a [Map]; nothing
//     inside is decoded before the signature checks out.
//   - [Map.Next] is how a running node takes a map from gossip: verified
//     against the trust the current map establishes, and accepted only if
//     it comes after it ([Accept]: same space, keys and key epoch, higher
//     version).
//   - [Map.Open] decrypts the one section sealed to a node's
//     [NodePrivateKey], checking only that it is well formed: builder policy
//     is Build's alone, so it can tighten without breaking deployed readers.
//
// A map is stored and passed on as the exact bytes from [Map.Bytes], never
// re-encoded.
//
// # The envelope
//
// One map per space: a signed envelope with a [Header], readable by anyone
// holding the envelope (space id, key epoch, version, the space's signing
// and recovery public keys, and the hashes of every blob the space uses),
// and one sealed section per node. The signature is Ed25519ctx by the
// space's signing key over the exact body bytes, with a context of its own
// so that no other signature of the space's keys passes for a map's. An
// envelope is canonical (body, then signature, then only recovery records)
// and at most [MaxEnvelopeSize] bytes.
//
// Each section is an anonymous sealed box (NaCl, X25519 and
// XSalsa20-Poly1305) to the node's map key, its own X25519 key, separate
// from its WireGuard key. Sections carry no recipient id: a node finds its
// own by trying to open each one, so nothing in the envelope links a
// section to a node, or a node's sections across versions. Open tries every
// section, so a map with two sections for one key is caught rather than
// read inconsistently, and a section names its space, key epoch and version
// inside, so it can't be moved into another map.
//
// # What a section holds
//
// Each section holds only what its node needs, every other node known by
// an opaque id:
//
//   - an entry gets the device ids it accepts ([Section].Inbound), the
//     transport's verifier for each one's credential (a hash or public key
//     where the transport allows, so a seized node can't impersonate its
//     peers; the shared secret for a symmetric transport), per-link
//     transport settings and shaping, and its forwarding table
//     ([Section].Routes);
//   - an exit gets the WireGuard keys and overlay addresses of the devices
//     allowed to use it ([Section].Peers);
//   - a device gets its rules, chains and rule presets, its reachable peers
//     with their candidate first hops ([Peer].Paths), and the entries'
//     endpoints ([Section].Links).
//
// Endpoints and listener addresses are IP literals: the controller
// resolves names, so nodes never ask DNS at dial time, past the tunnel.
// Transport settings and shaping are opaque bytes here, bounded in size;
// Build also decodes every shaping under package shaping's rules, so it
// never publishes shaping every node would refuse.
//
// # Versions and gossip
//
// Versions only go up (at most [MaxVersion]). Maps are ordered by
// (key epoch, version), and the epoch is to change only through a recovery
// record (below), so a stolen signing key can't freeze the space by
// signing the highest possible version. Nodes accept a valid envelope with
// a higher version from anyone, other nodes included, so a map spreads by
// gossip, but each node can open only its own section. A map is never
// rolled back, and it has no expiry, so offline networks keep working.
// Revocation is a new version without the node.
//
// # Padding
//
// The section count is padded with dummy sections to a power of two of at
// least 8 (8, 16, 32, … up to 1024), so the envelope doesn't show how many
// nodes a space has. Dummies are real sealed boxes to throwaway keys, so
// they look like real sections. Every section of an envelope is padded to
// the same length, a power of two of at least 8 KiB, and the sections are
// shuffled, so neither length nor position tells a real section from a
// dummy, or a relay's section from a device's. 8 KiB holds every section
// of a space at the PRD's scale (10 servers, 20 devices) with room to
// spare, so such spaces all look alike; a much larger space moves to a
// bigger bucket, and that bucket is what remains visible. Verify rejects
// envelopes that break these rules.
//
// # Format changes
//
// [Format] is 1. Every format keeps the format number and the header,
// with its layout, where format 1 has them (field 1 and field 2 of the
// body), so any node can tell which space and version a newer envelope is
// even when it can't read the rest; Verify reports such an envelope as
// [ErrUnsupportedFormat]. New fields are added without a bump and ignored
// by older nodes. Fields older nodes must not ignore are rolled out per
// section first: Build marks each section with the lowest reader that
// understands it ([SectionReader]), and Open refuses a section that needs
// a newer reader than the node's. A node that refuses its section keeps
// its last map and stops taking newer ones (revocations included), so a
// field whose absence would fail open is better kept out of the map by
// Build. The format number is bumped only after the release that reads the
// new format has rolled out through format-1 maps, so no node is left
// unable to read its space's maps.
//
// # Recovery key
//
// The header carries the public key of the space's recovery key, created
// with the space and kept offline by the admin, never on the controller.
// It can sign exactly one kind of record: "from key epoch N, the signing
// key is X". Nodes are to accept that record over the current signing key
// and move to the new epoch, so a lost or stolen controller is recovered by
// rotating to a new key instead of re-creating the space; a record for
// epoch N is rejected when the node's current epoch exceeds N, so an old
// record can't roll the key back. The recovery key signs with a context of
// its own, so neither kind of signature passes for the other. Not yet
// (TP-036): Verify rejects an envelope carrying recovery records as
// [ErrUnsupportedFormat], and [Accept] rejects any change of key epoch or
// keys ([ErrKeysChanged]).
package netmap
