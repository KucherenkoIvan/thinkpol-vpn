// Package netmap is the signed network map: the envelope, sealed per-node
// sections, signing, verification and gossip. See DESIGN.md "The signed map".
//
// Both planes use it: the controller builds maps, every node reads its own
// section without the controller. Pure Go, buildable for Android.
//
// The wire format is the protobuf schema in proto/thinkpol/netmap/v1; only
// this package encodes or decodes it. A map's life:
//
//   - [Build] seals each node's [Section] to that node's [NodePublicKey],
//     pads the sections to a power-of-two count of equal-length sealed boxes
//     in random order, and signs the result with the space's signing key.
//   - [Verify] checks the signature against the signing key the node trusts
//     and returns a [Map]; nothing inside is decoded before that.
//   - [Open] decrypts the one section sealed to a node's [NodePrivateKey].
//   - [Accept] decides whether a verified map may replace the one a node
//     runs: same space and keys, strictly higher version.
//
// A map is stored and passed on as the exact bytes from [Map.Bytes], never
// re-encoded.
package netmap
