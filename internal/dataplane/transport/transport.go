package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// MaxPacketSize is the largest packet every link carries. It leaves room for
// the path layer's header around a WireGuard packet of any sane MTU, and
// keeps datagram transports under common UDP send limits.
const MaxPacketSize = 8192

// MinSecretSize is the shortest link secret adapters accept.
const MinSecretSize = 32

var (
	// ErrPacketSize is returned by WritePacket for an empty packet or one
	// larger than MaxPacketSize.
	ErrPacketSize = errors.New("transport: packet size out of range")
	// ErrRevoked marks a link closed because its credential left the
	// listener's peer table.
	ErrRevoked = errors.New("transport: credential revoked")
	// ErrSuperseded marks a link closed because a newer link with the same
	// credential replaced it.
	ErrSuperseded = errors.New("transport: superseded by a newer link")
)

// ClosedError is the error a closed link returns: it matches net.ErrClosed,
// and reason (ErrRevoked, ErrSuperseded) when there is one.
func ClosedError(reason error) error {
	if reason == nil {
		return net.ErrClosed
	}
	return fmt.Errorf("%w: %w", net.ErrClosed, reason)
}

// Link is one authenticated link between two adjacent nodes. See the package
// documentation for the delivery contract.
type Link interface {
	// ReadPacket blocks until a packet arrives and copies it into p. A packet
	// that doesn't fit is dropped and io.ErrShortBuffer returned; a buffer of
	// MaxPacketSize bytes always fits.
	ReadPacket(p []byte) (int, error)
	// WritePacket sends p as one packet. It doesn't retain p.
	WritePacket(p []byte) error
	// Close closes the link and unblocks pending reads.
	Close() error
	// LocalAddr is this end's network address.
	LocalAddr() net.Addr
	// RemoteAddr is the peer's network address as last seen; datagram
	// transports follow a peer whose address changes (NAT rebinding).
	RemoteAddr() net.Addr
}

// Dialer opens links. One dialer serves every link of its transport.
type Dialer interface {
	// Dial opens a link to endpoint (host:port, as in the map).
	Dial(ctx context.Context, endpoint string, cfg LinkConfig) (Link, error)
}

// Listener accepts links from the peers in its table.
type Listener interface {
	// Accept waits for the next authenticated link and returns it with the
	// peer's identity from the table.
	Accept(ctx context.Context) (Link, Identity, error)
	// Addr is the address the listener receives on.
	Addr() net.Addr
	// Close stops the listener and closes every link it accepted. Pending
	// and later Accept calls return an error matching net.ErrClosed.
	Close() error
}

// Identity is who is at the other end of an accepted link. Both ids are
// opaque, as in the map.
type Identity struct {
	Space string
	Node  string
}

func (id Identity) String() string { return id.Space + "/" + id.Node }

// Credential authenticates one link. Both ends hold the same credential, from
// their sections of the map.
type Credential struct {
	// Secret is at least MinSecretSize random bytes. Adapters derive their
	// keys from it with a KDF and never use it directly as a key.
	Secret []byte
}

// Validate reports whether the credential is usable.
func (c Credential) Validate() error {
	if len(c.Secret) < MinSecretSize {
		return fmt.Errorf("transport: link secret is %d bytes, need at least %d", len(c.Secret), MinSecretSize)
	}
	return nil
}

// Shaping is how a link hides the size and rhythm of the packets it carries
// (C6): padding, batching, timing jitter, idle cover traffic. The sender
// applies it; receivers undo it from the wire format alone.
//
// Placeholder: the settings arrive with the shaping contract (TP-027). Until
// then the zero value, no shaping, is the only one. An adapter that can't
// honour a setting refuses the link instead of ignoring it.
type Shaping struct{}

// LinkConfig is everything the map says about one link, for either end.
type LinkConfig struct {
	Credential Credential
	Shaping    Shaping
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
	// camouflage owns conn from then on.
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

// CheckPacketSize returns ErrPacketSize unless p is a valid packet length.
func CheckPacketSize(p []byte) error {
	if len(p) == 0 || len(p) > MaxPacketSize {
		return fmt.Errorf("%w: %d bytes", ErrPacketSize, len(p))
	}
	return nil
}
