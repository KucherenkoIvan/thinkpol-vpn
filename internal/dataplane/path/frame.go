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
//	packet:      kind=1 | hop limit [1] | destination [8] | source [8] | WireGuard message
//	probe:       kind=2 | 0 [1] | token [8]
//	probe reply: kind=3 | 0 [1] | token [8]
//
// Packets travel end to end and relays forward them by destination; probes
// and their replies stay on one link. A frame of any other kind is dropped,
// so a kind added later is ignored by older nodes.
const (
	kindPacket     = 1
	kindProbe      = 2
	kindProbeReply = 3

	// HeaderSize is what the path layer adds to every WireGuard message.
	HeaderSize = 18
	// MaxMessageSize is the largest WireGuard message the path layer
	// carries: a link's packet minus the header.
	MaxMessageSize = transport.MaxPacketSize - HeaderSize
	// DefaultHopLimit is the hop limit a sender starts a packet with. Each
	// relay takes one off and none forwards a packet that would arrive with
	// zero, so a loop in the maps' routes drops a packet after at most
	// DefaultHopLimit-1 relays.
	DefaultHopLimit = 8

	probeSize = 10
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

// parsePacket reads a packet frame's header. It refuses frames too short to
// carry a message and frames that arrive with no hops left.
func parsePacket(f []byte) (header, bool) {
	if len(f) <= HeaderSize || f[0] != kindPacket || f[1] == 0 {
		return header{}, false
	}
	var h header
	h.hopLimit = f[1]
	copy(h.dst[:], f[2:10])
	copy(h.src[:], f[10:18])
	return h, true
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

// minOverlayMTU matches dataplane.MinOverlayMTU: the smallest overlay TUN
// MTU any node runs with. wireguard-go caps padding there, so a sender's
// full-MTU frame has at least this much content even when that MTU is not a
// multiple of 16.
const minOverlayMTU = 576

// wgDataLen reports whether n is a plausible WireGuard data message length.
// wireguard-go pads plaintext to min(roundup16(len), sender MTU) before
// sealing, so lengths are a multiple of 16 or a capped full-MTU on the
// sender (>= minOverlayMTU); the receiver's own MTU does not appear on the
// wire.
func wgDataLen(n int) bool {
	if n < 32 {
		return false
	}
	content := n - 32
	return content%16 == 0 || content >= minOverlayMTU
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
