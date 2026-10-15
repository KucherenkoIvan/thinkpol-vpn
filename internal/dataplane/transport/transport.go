package transport

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

// MaxPacketSize is the largest packet every link carries. It leaves room for
// the path layer's header around a WireGuard packet of any sane MTU, and
// keeps datagram transports under common UDP send limits.
const MaxPacketSize = 8192

var (
	// ErrPacketSize is returned by WritePacket for an empty packet or one
	// larger than MaxPacketSize.
	ErrPacketSize = errors.New("transport: packet size out of range")
	// ErrPacketTooLong is returned (wrapped) by WritePacket when the
	// network under the link refuses a packet as too long for its path
	// (EMSGSIZE): the overlay's MTU is above what this link carries.
	ErrPacketTooLong = errors.New("transport: packet too long for the network path")
	// ErrRevoked marks a link closed because its credential left the
	// listener's peer table.
	ErrRevoked = errors.New("transport: credential revoked")
	// ErrSuperseded marks a link closed because a newer link with the same
	// credential replaced it.
	ErrSuperseded = errors.New("transport: superseded by a newer link")
)

// ClosedError is the error a closed link returns: it matches net.ErrClosed,
// and cause (ErrRevoked, ErrSuperseded, an adapter's fatal error) when there
// is one.
func ClosedError(cause error) error {
	if cause == nil {
		return net.ErrClosed
	}
	return fmt.Errorf("%w: %w", net.ErrClosed, cause)
}

// CheckPacketSize returns ErrPacketSize unless p is a valid packet length.
func CheckPacketSize(p []byte) error {
	if len(p) == 0 || len(p) > MaxPacketSize {
		return fmt.Errorf("%w: %d bytes", ErrPacketSize, len(p))
	}
	return nil
}

// SpaceID and NodeID are the map's opaque ids; their sizes match netmap's,
// so converting is free, without this package importing netmap.
type (
	SpaceID [16]byte
	NodeID  [8]byte
)

func (id SpaceID) String() string { return hex.EncodeToString(id[:]) }
func (id NodeID) String() string  { return hex.EncodeToString(id[:]) }

// Identity is who is at the other end of an accepted link.
type Identity struct {
	Space SpaceID
	Node  NodeID
}

func (id Identity) String() string { return id.Space.String() + "/" + id.Node.String() }

// Link is one authenticated link between two adjacent nodes. See the package
// documentation for the contract.
type Link interface {
	// ReadPacket blocks until a packet arrives and copies it into p. A packet
	// that doesn't fit is dropped and io.ErrShortBuffer returned; a buffer of
	// MaxPacketSize bytes always fits.
	ReadPacket(p []byte) (int, error)
	// WritePacket sends p as one packet; it may block for backpressure. It
	// doesn't retain p.
	WritePacket(p []byte) error
	// Close closes the link and unblocks pending reads and writes.
	Close() error
	// LocalAddr is this end's network address.
	LocalAddr() net.Addr
	// RemoteAddr is the peer's network address as last seen; datagram
	// transports may follow a peer whose address changes.
	RemoteAddr() net.Addr
}

// ControlWriter is a Link that knows which packets keep the link warm or
// measure it (the path layer's probes and their replies, keepalives) rather
// than carry data. Their own rhythm is a fingerprint, so the transport may
// fit them into its shaping: pad and jitter them like data, hold one for up
// to MaxControlHold to ride with the next data or cover unit, or send it as
// the cover unit it would have sent anyway. The far end reads them as
// ordinary packets. Delivery is as for WritePacket.
//
// Only the layer above's own control packets go this way: WireGuard's
// handshakes, keepalives and data are always WritePacket. And because a
// control packet may be held at each end, a round trip timed with control
// packets is an upper bound, off by up to 2 × MaxControlHold plus both
// ends' Shaping.MaxDelay: liveness can rest on it, latency comparisons
// must not. Latency is measured on traffic that isn't held (WritePacket
// on both ends, e.g. WireGuard's handshake round trip), on links whose
// shaping has no batching or jitter, or compared only beyond that bound.
type ControlWriter interface {
	WriteControl(p []byte) error
}

// MaxControlHold is the longest a ControlWriter holds a control packet.
// Probe timeouts above the transport must allow for it twice (probe and
// reply).
const MaxControlHold = 500 * time.Millisecond

// WriteControl sends a control packet on l: with WriteControl if l is a
// ControlWriter, otherwise as an ordinary packet.
func WriteControl(l Link, p []byte) error {
	if cw, ok := l.(ControlWriter); ok {
		return cw.WriteControl(p)
	}
	return l.WritePacket(p)
}

// DialConfig is what the map gives the dialing end of one link.
type DialConfig struct {
	// Credential is what the dialer proves itself with.
	Credential []byte
	// Settings is the transport's own settings message for the link,
	// encoded by the controller and decoded by the adapter.
	Settings []byte
	// Shaping is how this end shapes what it sends.
	Shaping Shaping
}

// Dialer opens links. One dialer serves every link of its transport.
type Dialer interface {
	// Dial opens a link to endpoint (an IP literal and port, as in the
	// map).
	Dial(ctx context.Context, endpoint string, cfg DialConfig) (Link, error)
}

// Listener accepts links from the peers in its table.
type Listener interface {
	// Accept waits for the next authenticated link and returns it with the
	// peer's identity from the table. The link may already be closed, e.g.
	// revoked between its first packet and Accept.
	Accept(ctx context.Context) (Link, Identity, error)
	// Addr is the address the listener receives on.
	Addr() net.Addr
	// Close stops the listener and closes every link it accepted. Pending
	// and later Accept calls return an error matching net.ErrClosed.
	Close() error
}

// Camouflage is what an unauthenticated peer gets: anything that fails a
// listener's authentication is handed here instead of being answered.
// Implementations must not block the listener for long.
type Camouflage interface {
	// Datagram receives one datagram that failed authentication, from a
	// datagram transport. p is valid only during the call.
	Datagram(p []byte, from net.Addr)
	// Stream takes over a stream connection that failed authentication;
	// consumed holds the bytes the transport already read from it. The
	// camouflage owns conn from then on; one meant only for datagrams
	// closes it.
	Stream(conn net.Conn, consumed []byte)
}

// Drop is the camouflage of silence: datagrams vanish, streams are closed.
type Drop struct{}

func (Drop) Datagram([]byte, net.Addr) {}

func (Drop) Stream(conn net.Conn, _ []byte) { _ = conn.Close() }

// OrDrop returns c, or Drop if c is nil.
func OrDrop(c Camouflage) Camouflage {
	if c == nil {
		return Drop{}
	}
	return c
}

// StaleClockSource is implemented by a Link, Listener or Router of a
// transport that authenticates freshness against its own clock (DESIGN:
// nodes' clocks must agree within five minutes). StaleClock returns how
// many datagrams it dropped as sealed outside its clock margin since it
// opened: a peer's clock disagrees with its own beyond the margin, or
// datagrams were replayed from older than that. The data plane turns it
// into the clock-skew health problem.
type StaleClockSource interface {
	StaleClock() uint64
}

// StaleClockAtSource is a StaleClockSource that records when the last
// stale-clock drop happened on its own clock (not when something else read
// the count).
type StaleClockAtSource interface {
	StaleClockSource
	StaleClockAt() time.Time
}
