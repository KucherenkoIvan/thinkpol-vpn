// Package blobs fetches content-addressed files (lists, later releases)
// from peers by hash, verifies, caches and serves them, with no outside
// server (PRD R9, A9; DESIGN.md "Lists").
//
// The signed map says which blobs exist: its header lists every blob the
// space uses (the availability set servers hold and pass on), and each
// section names the blobs its node uses. A [Service] holds what its node's
// map asks for ([Plan].Want, from [PlanFrom]), fetches what it lacks from
// the node's WireGuard peers through the overlay, checks every blob against
// its reference (size, SHA-256, and for a GeoIP list that it decodes)
// before holding or serving it, and serves what it holds to its peers.
// Nodes fetch only from peers, never from outside the network.
//
// # Roles
//
// Servers serve. A server's worker holds the header's whole set: from the
// seeds in its state directory, which the supervisor sends it, or fetched
// from other servers. It answers on its own overlay addresses, only to its
// WireGuard peers, and only for blobs it holds, all of which a signed map
// of its space listed.
//
// Devices only fetch: a device holds the blobs its section names, and
// nothing on a device answers on the blob port ([Plan].Listen is empty).
//
// # Protocol
//
// TCP on the overlay, port [Port] (4717), to a peer's overlay address:
// inside WireGuard, so the far end is the peer WireGuard authenticated, and
// nothing about it shows on the wire beyond ordinary tunnel traffic. Both
// sockets are bound to the overlay's TUN, so only traffic through the
// tunnel reaches the service and nothing it sends can leave another way.
// One request per connection, for one blob by its SHA-256:
//
//	request:  "TPB" | version 1 | SHA-256 [32] | offset [8, big endian]
//	response: status [1] | (statusOK only) length [8, big endian] | the blob's bytes from offset on
//
// A server answers statusOK only for a blob it holds, which is always one
// a signed map of the space listed; anything else gets statusNotHere,
// whether the hash is unknown or merely not held, so the service is no
// oracle beyond the availability set the peer already has. Only the
// current plan's peers are served, by overlay address: a connection from
// any other source is closed unanswered, and a transfer stops as soon as
// a new plan no longer has its peer. The length is the blob's size less
// the offset; the client knows the size from its own map and refuses any
// other. offset lets a client resume a transfer that broke (up to three
// times from the same peer); the whole blob is checked once it is
// complete.
//
// # Fetching
//
// A node fetches the blobs its map asks for in the map's order, from its
// section's WireGuard peers in order (each at its overlay addresses, IPv4
// first, IPv6 only while the overlay carries it). It uses a blob only once
// its size and SHA-256 match the map, and a GeoIP list decodes. A peer that
// doesn't hold the blob, is busy, sends anything else, or trickles below
// [Limits].MinRate on average (a transfer of n bytes gets DialTimeout plus
// n/MinRate in all) is skipped for the next. A good copy in the node's
// [Store] is used before any peer is asked. A blob that matches its
// reference but doesn't decode is the map's fault, not a peer's: it is not
// fetched again until the map changes. A new map abandons a transfer under
// way. While something is missing the rounds repeat with a backoff.
//
// A list in use is replaced only once its successor is verified: the
// previous map's blobs stay held only until every blob the current map
// asks for is held. On a device that holds across restarts too: the
// [Store] keeps the blobs the node uses, and its index is where the
// previous version of a list comes from while the current map's isn't held
// yet.
//
// # Bounds
//
// A blob is at most [Limits].MaxBlob bytes ([MaxBlobSize], 16 MiB) and the
// blobs the current map asks for at most [Limits].MaxHeld together:
// [MaxHeldSize] (64 MiB) on a device, [ServerMaxHeldSize] (16 MiB) on a
// server, where the header's whole set is held in a worker's memory per
// space and the map builder keeps the header within it. More is skipped
// and reported. A server serves at most [Limits].MaxConns connections at
// once (16), [Limits].MaxConnsPerPeer per peer address (2), past which a
// request is answered busy, at [Limits].ServeRate bytes per second for all
// of them together ([DefaultServeRate], 2 MiB/s); a client fetches one
// blob at a time, one peer at a time.
//
// # What it shows
//
// The header's hashes are visible to every node holding the envelope. For
// public lists that tells a node only that the space uses, say, a Russian
// GeoIP list: an accepted leak (DESIGN.md "Residual risks").
package blobs
