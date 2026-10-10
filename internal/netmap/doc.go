// Package netmap is the signed network map: the envelope, sealed per-node
// sections, signing, verification and gossip. See DESIGN.md "The signed map".
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
package netmap
