package path

import (
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// NodeID is the map's opaque node id, as the transport port names it.
type NodeID = transport.NodeID

// Frames are what the path layer puts inside a link's packets. The link
// seals them, so none of this is visible on the wire.
//
//	packet:          kind=6 | hop limit [1] | destination [8] | source [8] | seq [4] | ack [4] | WireGuard message
//	probe, reply:    kind=2, 3 | flags [1] | token [8] | seq [4] | ack [4]
//	older packet:    kind=1 | hop limit [1] | destination [8] | source [8] | WireGuard message
//	older probe:     kind=2, 3 | flags [1] | token [8]
//
// Flags: bit 0, the sender reads acks; bit 1, a close notice (a probe the
// far end obeys by closing the link, without a reply). Seq and ack are per
// link and serial numbers (RFC 1982): seq counts the frames a link writes
// in the newer format, from a random start, and ack is the newest seq the
// link has read from the far end (docs/design/path-liveness.md, "Acks in
// the frames"). A link writes the older frames, which older nodes read,
// until the far end shows it reads acks. An older probe with bit 0 set
// carries the sender's first seq less one in the first four bytes of its
// token, so a far end that switches on it has an ack to send before any
// newer frame arrives.
//
// Packets travel end to end and relays forward them by destination; probes
// and their replies stay on one link. A frame of any other kind is dropped,
// so a kind added later is ignored by older nodes.
const (
	kindPacketV1   = 1
	kindProbe      = 2
	kindProbeReply = 3
	kindPacket     = 6

	flagReadsAcks = 1 << 0
	flagClosing   = 1 << 1

	// HeaderSize is what the path layer adds to every WireGuard message.
	HeaderSize = 26
	// headerSizeV1 is the older packet's header: no seq or ack.
	headerSizeV1 = 18
	// seqAckSize is what seq and ack add to a frame.
	seqAckSize = HeaderSize - headerSizeV1
	// MaxMessageSize is the largest WireGuard message the path layer
	// carries: a link's packet minus the header.
	MaxMessageSize = transport.MaxPacketSize - HeaderSize
	// DefaultHopLimit is the hop limit a sender starts a packet with. Each
	// relay takes one off and none forwards a packet that would arrive with
	// zero, so a loop in the maps' routes drops a packet after at most
	// DefaultHopLimit-1 relays.
	DefaultHopLimit = 8

	probeSize   = 18
	probeSizeV1 = 10

	// keepaliveSize is a WireGuard keepalive's length: a data message with
	// no payload. Relays tell keepalives by length alone, and a frame
	// carrying one expects no answer.
	keepaliveSize = 32

	// MinOverlayMTU is the smallest overlay TUN MTU any node runs with;
	// wireguard-go caps padding there, so path's data-frame length rule
	// keys off it.
	MinOverlayMTU = 576
)

type header struct {
	hopLimit uint8
	dst, src NodeID
}

func putHeader(b []byte, h header) {
	b[0] = kindPacket
	b[1] = h.hopLimit
	copy(b[2:10], h.dst[:])
	copy(b[10:18], h.src[:])
}

// parsePacket reads a packet frame's header, of either format, and where
// its message starts. It refuses frames too short to carry a message and
// frames that arrive with no hops left.
func parsePacket(f []byte) (header, int, bool) {
	var off int
	switch f[0] {
	case kindPacket:
		off = HeaderSize
	case kindPacketV1:
		off = headerSizeV1
	default:
		return header{}, 0, false
	}
	if len(f) <= off || f[1] == 0 {
		return header{}, 0, false
	}
	var h header
	h.hopLimit = f[1]
	copy(h.dst[:], f[2:10])
	copy(h.src[:], f[10:18])
	return h, off, true
}

// seqAck returns where a newer-format frame keeps its seq and ack, or -1
// for a frame without them.
func seqAck(f []byte) int {
	switch {
	case f[0] == kindPacket && len(f) > HeaderSize:
		return headerSizeV1
	case (f[0] == kindProbe || f[0] == kindProbeReply) && len(f) == probeSize:
		return probeSizeV1
	}
	return -1
}

// toV1 rewrites a packet frame in place into the older format and returns
// it: the header moves up over seq and ack. f must be a newer packet.
func toV1(f []byte) []byte {
	copy(f[seqAckSize:HeaderSize], f[:headerSizeV1])
	f[seqAckSize] = kindPacketV1
	return f[seqAckSize:]
}

// fromV1 rewrites an older packet frame into the newer format, in the
// same buffer (cap(f) must allow seqAckSize more), and returns it; seq and
// ack are left for the writer.
func fromV1(f []byte) []byte {
	n := len(f)
	f = f[:n+seqAckSize]
	copy(f[HeaderSize:], f[headerSizeV1:n])
	f[0] = kindPacket
	return f
}

// Frame buffers: one size for every frame, recycled from the moment a link
// has written them or a WireGuard device has copied them out.
var bufPool = sync.Pool{New: func() any {
	b := make([]byte, transport.MaxPacketSize)
	return &b
}}

func getBuf() *[]byte {
	b := bufPool.Get().(*[]byte)
	*b = (*b)[:cap(*b)]
	return b
}

func putBuf(b *[]byte) { bufPool.Put(b) }

// WireGuard message types, read only to tell what a message is for: the
// path layer never looks further into one.
const (
	wgInitiation = 1
	wgResponse   = 2
	wgCookie     = 3
	wgData       = 4
)

// wgDataLen reports whether n is a plausible WireGuard data message length.
// wireguard-go pads plaintext to min(roundup16(len), sender MTU) before
// sealing, so lengths are a multiple of 16 or a capped full-MTU on the
// sender (>= MinOverlayMTU); the receiver's own MTU does not appear on the
// wire.
func wgDataLen(n int) bool {
	if n < 32 {
		return false
	}
	content := n - 32
	return content%16 == 0 || content >= MinOverlayMTU
}

// wgType returns the type of a message shaped like a WireGuard message
// (its type, three zero bytes, and its type's size), or 0. The shape is no
// proof: anything can be shaped so. It keeps plainly malformed junk from
// counting as a sign of life.
func wgType(m []byte) byte {
	if len(m) < 4 || m[1] != 0 || m[2] != 0 || m[3] != 0 {
		return 0
	}
	switch t := m[0]; {
	case t == wgInitiation && len(m) == 148,
		t == wgResponse && len(m) == 92,
		t == wgCookie && len(m) == 64,
		t == wgData && wgDataLen(len(m)):
		return t
	}
	return 0
}

// MessageBudget is the largest WireGuard message a link of t with shaping
// s carries in units of at most maxUnit bytes (for a datagram transport,
// the path MTU less the IP and UDP headers): transport.MaxPacket less
// HeaderSize, never more than MaxMessageSize, never negative. WireGuard's
// own data overhead (32 bytes) comes off it for the TUN's MTU.
func MessageBudget(t transport.Transport, s transport.Shaping, maxUnit int) int {
	return max(min(transport.MaxPacket(t, s, maxUnit)-HeaderSize, MaxMessageSize), 0)
}
