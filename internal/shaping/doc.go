// Package shaping holds the rules of the map's shaping message,
// thinkpol.transport.v1.Shaping (PRD C6, docs/design/transports.md "Transports own traffic
// shape"), in one place for both its users: netmap's builder, which never
// publishes shaping no node could read, and the transport port
// (internal/dataplane/transport), which turns it into a transport.Shaping
// and whose adapters say what they implement of it. It imports only the
// generated message, so the map and the control plane can use it without
// depending on the data plane.
//
// # The message
//
// A Shaping message says how one end of a link shapes what it sends; the
// map carries one per end, in a shaping field next to the transport's
// settings (empty bytes: no shaping). It may ask for:
//
//   - padding of each unit on the wire, either up to the smallest of 1 to
//     [MaxBuckets] bucket sizes (strictly ascending, each 1 to [MaxUnit]
//     bytes), or by a random number of bytes in [min, max] (max at least
//     1 and at most [MaxUnit]);
//   - a batching window and timing jitter, each in whole microseconds and
//     at most [MaxDelay], since more would stall the TCP connections
//     inside the tunnel;
//   - cover traffic on an idle link, every [MinCoverInterval] to
//     [MaxCoverInterval] (zero: none).
//
// [Check] applies these rules (errors match [ErrInvalid]). [Decode] reads
// an encoded message strictly and then checks it.
//
// # Unknown fields are refused
//
// Decode refuses a message carrying fields this node doesn't know, at any
// depth, with [ErrUnsupported]: a node too old for a setting refuses the
// link rather than ignore the setting and shape less than the map asks.
// That is safe only because the controller never asks a node for shaping
// it can't do: it puts a shaping, or a new shaping field or value, into a
// link only once both ends' nodes reported supporting it
// (docs/design/transports.md "Transports own traffic shape"). The builder decodes every shaping it
// publishes with the same rules, so a map never carries shaping that every
// node would refuse.
package shaping
