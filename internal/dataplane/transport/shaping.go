package transport

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

var (
	// ErrInvalidShaping marks shaping settings that make no sense on any
	// transport.
	ErrInvalidShaping = errors.New("transport: invalid shaping")
	// ErrUnsupportedShaping marks shaping settings a transport can't honour.
	// It refuses the link rather than shaping less than asked.
	ErrUnsupportedShaping = errors.New("transport: shaping not supported")
)

// Shaping is how one end of a link shapes what it sends (C6): the sizes and
// rhythm of the units the transport puts on the wire (datagrams, records).
// Each end has its own: the dialing end's comes with its [DialConfig], the
// listening end's with its [PeerLink]. Receivers undo any shaping from the
// wire format alone, so the ends never negotiate and need not agree. The
// zero value is no shaping; the map encodes it as the protobuf message
// thinkpol.transport.v1.Shaping ([ParseShaping]).
//
// An adapter honours every setting it accepts and refuses, with
// [ErrUnsupportedShaping], a link that asks for one it doesn't implement
// ([ShapingSupport]). Padding and cover units are inside the transport's
// encryption, so shaping never weakens its authentication or replay
// protection.
type Shaping struct {
	Padding Padding
	// BatchWindow is how long the sender may hold a packet to send it
	// together with the next ones in one unit. Zero: never.
	BatchWindow time.Duration
	// Jitter is the most a unit is delayed, chosen uniformly at random per
	// unit. Zero: never.
	Jitter time.Duration
	// CoverInterval is how often, about, an idle link sends a unit that
	// carries no packet. Zero: no cover traffic.
	CoverInterval time.Duration
}

// PaddingMode is how a sender grows the units it sends.
type PaddingMode uint8

const (
	// PadNone sends units as they are.
	PadNone PaddingMode = iota
	// PadToBuckets grows each unit to the smallest bucket that holds it;
	// units larger than every bucket go as they are.
	PadToBuckets
	// PadRandom grows each unit by a uniformly random number of bytes in
	// [Min, Max].
	PadRandom
)

// MaxBuckets is the most bucket sizes a padding has.
const MaxBuckets = 16

// Shaping limits that hold for every transport; adapters may be stricter.
const (
	// MaxShapingDelay bounds BatchWindow and Jitter: more would stall the
	// TCP connections inside the tunnel.
	MaxShapingDelay = time.Second
	// MinCoverInterval and MaxCoverInterval bound CoverInterval.
	MinCoverInterval = 10 * time.Millisecond
	MaxCoverInterval = time.Hour
)

// Padding is how a sender grows the units it sends, inside their
// encryption. Sizes are of the unit on the wire: for a datagram transport
// the UDP payload, for a stream transport the record it writes.
type Padding struct {
	Mode PaddingMode
	// Buckets are the unit sizes of PadToBuckets, strictly ascending; the
	// entries after the last are zero.
	Buckets [MaxBuckets]uint16
	// Min and Max bound what PadRandom adds.
	Min, Max uint16
}

// Size is the size of a unit of size bytes once padded.
func (p Padding) Size(size int) int {
	switch p.Mode {
	case PadToBuckets:
		for _, b := range p.Buckets {
			if b == 0 {
				break
			}
			if int(b) >= size {
				return int(b)
			}
		}
	case PadRandom:
		return size + int(p.Min) + rand.IntN(int(p.Max-p.Min)+1) //nolint:gosec // sizes, not secrets: the unit is encrypted either way
	}
	return size
}

// Growth is the most padding adds to a unit that no bucket rounds up:
// what a transport's Overhead counts for it.
func (p Padding) Growth() int {
	if p.Mode == PadRandom {
		return int(p.Max)
	}
	return 0
}

// ceiling is the largest unit, at most maxUnit bytes, whose padded size
// is at most maxUnit too, as far as buckets go.
func (p Padding) ceiling(maxUnit int) int {
	if p.Mode != PadToBuckets {
		return maxUnit
	}
	below, above := 0, false
	for _, b := range p.Buckets {
		switch {
		case b == 0:
		case int(b) <= maxUnit:
			below = int(b)
		default:
			above = true
		}
	}
	if !above {
		return maxUnit
	}
	return below
}

// MaxPacket is the largest packet a link of t with shaping s sends in
// units of at most maxUnit bytes: for a datagram transport, the path's MTU
// less the IP and UDP headers. The path layer budgets WireGuard's MTU from
// it. It is 0 when s pads every packet past maxUnit (a bucket above
// maxUnit with none at or below it).
//
// Overhead(s) alone is not the budget under bucket padding: a packet that
// fits maxUnit unpadded still goes to the next bucket, which may not.
func MaxPacket(t Transport, s Shaping, maxUnit int) int {
	return min(max(s.Padding.ceiling(maxUnit)-t.Overhead(s), 0), MaxPacketSize)
}

// IsZero reports whether s is no shaping.
func (s Shaping) IsZero() bool { return s == Shaping{} }

// Validate checks s against the rules every transport shares; errors match
// ErrInvalidShaping.
func (s Shaping) Validate() error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidShaping, fmt.Sprintf(format, args...))
	}
	p := s.Padding
	switch p.Mode {
	case PadNone:
		if p != (Padding{}) {
			return invalid("padding sizes without a padding mode")
		}
	case PadToBuckets:
		if p.Min != 0 || p.Max != 0 {
			return invalid("random bounds on bucket padding")
		}
		if p.Buckets[0] == 0 {
			return invalid("bucket padding without buckets")
		}
		for i := 1; i < MaxBuckets; i++ {
			b, prev := p.Buckets[i], p.Buckets[i-1]
			if b != 0 && (prev == 0 || b <= prev) {
				return invalid("buckets not strictly ascending: %d after %d", b, prev)
			}
		}
	case PadRandom:
		if p.Buckets != ([MaxBuckets]uint16{}) {
			return invalid("buckets on random padding")
		}
		if p.Max == 0 || p.Min > p.Max {
			return invalid("random padding of [%d, %d] bytes", p.Min, p.Max)
		}
	default:
		return invalid("padding mode %d", p.Mode)
	}
	for name, d := range map[string]time.Duration{"batch window": s.BatchWindow, "jitter": s.Jitter} {
		if d < 0 || d > MaxShapingDelay || d%time.Microsecond != 0 {
			return invalid("%s of %v (whole microseconds up to %v)", name, d, MaxShapingDelay)
		}
	}
	if c := s.CoverInterval; c != 0 && (c < MinCoverInterval || c > MaxCoverInterval || c%time.Microsecond != 0) {
		return invalid("cover interval of %v (whole microseconds, %v to %v)", c, MinCoverInterval, MaxCoverInterval)
	}
	return nil
}

// ShapingSupport is what an adapter's shaping implements.
type ShapingSupport struct {
	Padding, Batching, Jitter, Cover bool
}

// Check returns an error unless s is valid and asks only for what the
// adapter implements; unsupported settings match ErrUnsupportedShaping.
func (sup ShapingSupport) Check(s Shaping) error {
	if err := s.Validate(); err != nil {
		return err
	}
	for _, c := range []struct {
		name      string
		asked, ok bool
	}{
		{"padding", s.Padding.Mode != PadNone, sup.Padding},
		{"batching", s.BatchWindow != 0, sup.Batching},
		{"timing jitter", s.Jitter != 0, sup.Jitter},
		{"cover traffic", s.CoverInterval != 0, sup.Cover},
	} {
		if c.asked && !c.ok {
			return fmt.Errorf("%w: %s", ErrUnsupportedShaping, c.name)
		}
	}
	return nil
}

// ParseShaping decodes the map's thinkpol.transport.v1.Shaping; empty
// bytes are no shaping. It rejects fields it doesn't know, so a node too old
// for a setting refuses the link instead of ignoring the setting.
func ParseShaping(b []byte) (Shaping, error) {
	var s Shaping
	if len(b) == 0 {
		return s, nil
	}
	var pb transportv1.Shaping
	if err := proto.Unmarshal(b, &pb); err != nil {
		return s, fmt.Errorf("%w: %w", ErrInvalidShaping, err)
	}
	if hasUnknown(pb.ProtoReflect()) {
		return s, fmt.Errorf("%w: settings this node doesn't know", ErrUnsupportedShaping)
	}
	switch p := pb.GetPadding().(type) {
	case *transportv1.Shaping_Buckets:
		sizes := p.Buckets.GetSizes()
		if len(sizes) > MaxBuckets {
			return s, fmt.Errorf("%w: %d buckets, at most %d", ErrInvalidShaping, len(sizes), MaxBuckets)
		}
		s.Padding.Mode = PadToBuckets
		for i, size := range sizes {
			if size == 0 || size > 0xffff {
				return s, fmt.Errorf("%w: bucket of %d bytes", ErrInvalidShaping, size)
			}
			s.Padding.Buckets[i] = uint16(size)
		}
	case *transportv1.Shaping_Random:
		lo, hi := p.Random.GetMin(), p.Random.GetMax()
		if lo > 0xffff || hi > 0xffff {
			return s, fmt.Errorf("%w: random padding of [%d, %d] bytes", ErrInvalidShaping, lo, hi)
		}
		s.Padding = Padding{Mode: PadRandom, Min: uint16(lo), Max: uint16(hi)}
	}
	s.BatchWindow = time.Duration(pb.GetBatchWindowUs()) * time.Microsecond
	s.Jitter = time.Duration(pb.GetJitterUs()) * time.Microsecond
	s.CoverInterval = time.Duration(pb.GetCoverIntervalUs()) * time.Microsecond
	if err := s.Validate(); err != nil {
		return Shaping{}, err
	}
	return s, nil
}

func hasUnknown(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	unknown := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Message() != nil && !fd.IsList() && !fd.IsMap() {
			unknown = hasUnknown(v.Message())
		}
		return !unknown
	})
	return unknown
}

// Marshal encodes s as the map carries it: what the controller writes and
// ParseShaping reads. No shaping is empty.
func (s Shaping) Marshal() []byte {
	if s.IsZero() {
		return nil
	}
	pb := &transportv1.Shaping{
		BatchWindowUs:   uint32(s.BatchWindow / time.Microsecond),
		JitterUs:        uint32(s.Jitter / time.Microsecond),
		CoverIntervalUs: uint32(s.CoverInterval / time.Microsecond),
	}
	switch s.Padding.Mode {
	case PadToBuckets:
		var sizes []uint32
		for _, b := range s.Padding.Buckets {
			if b != 0 {
				sizes = append(sizes, uint32(b))
			}
		}
		pb.Padding = &transportv1.Shaping_Buckets{Buckets: &transportv1.PadToBuckets{Sizes: sizes}}
	case PadRandom:
		pb.Padding = &transportv1.Shaping_Random{Random: &transportv1.PadRandom{Min: uint32(s.Padding.Min), Max: uint32(s.Padding.Max)}}
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(pb)
	if err != nil {
		panic(err) // a message of scalars always encodes
	}
	return b
}

// Buckets returns bucket padding to sizes, for tests and tools; it panics
// on more than MaxBuckets sizes or one above 65535.
func Buckets(sizes ...int) Padding {
	p := Padding{Mode: PadToBuckets}
	if len(sizes) > MaxBuckets {
		panic("transport: too many buckets")
	}
	for i, size := range sizes {
		if size < 0 || size > 0xffff {
			panic("transport: bucket size out of range")
		}
		p.Buckets[i] = uint16(size)
	}
	return p
}

// SendStats is what one end of a link, or a listener's links together,
// put on the wire, and what shaping cost: the overhead the lab weighs
// against what shaping hides.
type SendStats struct {
	Units        uint64 // datagrams or records
	Packets      uint64
	PacketBytes  uint64
	PaddingBytes uint64
	WireBytes    uint64 // whole units, before IP and UDP or TCP headers
}

// Overhead is the wire bytes per packet byte, less one: 0.25 means a
// quarter more on the wire than the packets themselves.
func (s SendStats) Overhead() float64 {
	if s.PacketBytes == 0 {
		return 0
	}
	return float64(s.WireBytes)/float64(s.PacketBytes) - 1
}

// SendMeter counts SendStats; it is safe for concurrent use.
type SendMeter struct {
	units, packets, packetBytes, paddingBytes, wireBytes atomic.Uint64
}

// Sent counts one unit.
func (m *SendMeter) Sent(packets, packetBytes, paddingBytes, wireBytes int) {
	m.units.Add(1)
	m.packets.Add(uint64(packets))
	m.packetBytes.Add(uint64(packetBytes))
	m.paddingBytes.Add(uint64(paddingBytes))
	m.wireBytes.Add(uint64(wireBytes))
}

// Stats returns the counts so far.
func (m *SendMeter) Stats() SendStats {
	return SendStats{
		Units:        m.units.Load(),
		Packets:      m.packets.Load(),
		PacketBytes:  m.packetBytes.Load(),
		PaddingBytes: m.paddingBytes.Load(),
		WireBytes:    m.wireBytes.Load(),
	}
}
