// Package blobs fetches content-addressed files (lists, later releases)
// from peers by hash, verifies, caches and serves them, with no outside
// server (PRD R9, A9; DESIGN.md "Lists").
//
// The signed map says which blobs exist: its header lists every blob the
// space uses (the availability set servers hold and pass on), and each
// section names the blobs its node uses. A Service holds what its node's
// map asks for (Plan.Want), fetches what it lacks from the node's WireGuard
// peers through the overlay, checks every blob against its reference
// (size, SHA-256, and for a GeoIP list that it decodes) before holding or
// serving it, and serves what it holds to its peers.
//
// # Protocol
//
// TCP on the overlay, port Port, to a peer's overlay address: inside
// WireGuard, so the far end is the peer WireGuard authenticated, and
// nothing about it shows on the wire beyond ordinary tunnel traffic. Both
// sockets are bound to the overlay's TUN, so only traffic through the
// tunnel reaches the service and nothing it sends can leave another way.
// One request per connection:
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
// other. offset lets a client resume a transfer that broke; the whole
// blob is checked once it is complete.
//
// # Bounds
//
// A blob is at most Limits.MaxBlob bytes and the blobs the current map
// asks for at most Limits.MaxHeld together (more is skipped and reported);
// the previous map's blobs stay held only until every blob the current map
// asks for is held, so a list in use is replaced only once its successor is
// verified. A server serves at most Limits.MaxConns connections at once,
// Limits.MaxConnsPerPeer per peer address, at Limits.ServeRate bytes per
// second for all of them together; a client fetches one blob at a time,
// one peer at a time, and backs off between rounds while something is
// missing.
package blobs
