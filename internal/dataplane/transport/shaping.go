package transport

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/shaping"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

var (
	// ErrInvalidShaping marks shaping settings that make no sense on any
	// transport.
	ErrInvalidShaping = shaping.ErrInvalid
	// ErrUnsupportedShaping marks shaping settings a transport can't honour.
	// It refuses the link rather than shaping less than asked.
	ErrUnsupportedShaping = shaping.ErrUnsupported
	// ErrSettingsRefused marks a live link closed because the table changed
	// its settings or shaping to something the transport refuses (the
	// cause wraps why); its credential is still in the table.
	ErrSettingsRefused = errors.New("transport: new link settings refused")
)

// Shaping is how one end of a link shapes what it sends (C6): the sizes and
// rhythm of the units the transport puts on the wire (datagrams, records).
// Each end has its own: the dialing end's comes with its [DialConfig], the
// listening end's with its [PeerLink]. Receivers undo any shaping from the
// wire format alone, so the ends never negotiate and need not agree. The
// zero value is no shaping; the map encodes it as the protobuf message
// thinkpol.transport.v1.Shaping ([ParseShaping], [Shaping.Marshal]), whose
// rules live in package internal/shaping.
//
// An adapter honours every setting it accepts and refuses, with
// [ErrUnsupportedShaping], a link that asks for one it doesn't implement
// ([ShapingSupport]). Padding and cover units are inside the transport's
// encryption, so shaping never weakens its authentication or replay
// protection.
//
// Batching, jitter and held control packets delay what a link carries, so
// a round trip measured through a shaped link is an upper bound: see
// [Shaping.MaxDelay] and [ControlWriter].
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

// Shaping limits that hold for every transport; adapters may be stricter.
const (
	// MaxBuckets is the most bucket sizes a padding has.
	MaxBuckets = shaping.MaxBuckets
	// MaxShapingDelay bounds BatchWindow and Jitter: more would stall the
	// TCP connections inside the tunnel.
	MaxShapingDelay = shaping.MaxDelay
	// MinCoverInterval and MaxCoverInterval bound CoverInterval.
	MinCoverInterval = shaping.MinCoverInterval
	MaxCoverInterval = shaping.MaxCoverInterval
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
		// math/rand/v2's global source is ChaCha8, seeded by the runtime from
		// the OS: an observer can't predict it, which is all a padding length
		// needs, and it costs no system call per packet.
		return size + int(p.Min) + rand.IntN(int(p.Max-p.Min)+1) //nolint:gosec // see above
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

// MaxDelay is the most this end's shaping delays a packet before it leaves:
// BatchWindow plus Jitter. A control packet ([ControlWriter]) may wait up to
// MaxControlHold more. A round trip measured through shaped links is an
// upper bound, off by up to both ends' MaxDelay.
func (s Shaping) MaxDelay() time.Duration { return s.BatchWindow + s.Jitter }

// IsZero reports whether s is no shaping.
func (s Shaping) IsZero() bool { return s == Shaping{} }

// Validate checks s against the rules every transport shares; errors match
// ErrInvalidShaping.
func (s Shaping) Validate() error {
	_, err := s.message()
	return err
}

// message is s as the map's message, checked.
func (s Shaping) message() (*transportv1.Shaping, error) {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidShaping, fmt.Sprintf(format, args...))
	}
	pb := &transportv1.Shaping{}
	p := s.Padding
	switch p.Mode {
	case PadNone:
		if p != (Padding{}) {
			return nil, invalid("padding sizes without a padding mode")
		}
	case PadToBuckets:
		if p.Min != 0 || p.Max != 0 {
			return nil, invalid("random bounds on bucket padding")
		}
		var sizes []uint32
		for i, b := range p.Buckets {
			if b == 0 {
				if i+1 < MaxBuckets && p.Buckets[i+1] != 0 {
					return nil, invalid("a zero bucket before %d", p.Buckets[i+1])
				}
				continue
			}
			sizes = append(sizes, uint32(b))
		}
		pb.Padding = &transportv1.Shaping_Buckets{Buckets: &transportv1.PadToBuckets{Sizes: sizes}}
	case PadRandom:
		if p.Buckets != ([MaxBuckets]uint16{}) {
			return nil, invalid("buckets on random padding")
		}
		pb.Padding = &transportv1.Shaping_Random{Random: &transportv1.PadRandom{Min: uint32(p.Min), Max: uint32(p.Max)}}
	default:
		return nil, invalid("padding mode %d", p.Mode)
	}
	us := func(name string, d, limit time.Duration) (uint32, error) {
		if d < 0 || d > limit || d%time.Microsecond != 0 {
			return 0, invalid("%s of %v (whole microseconds up to %v)", name, d, limit)
		}
		return uint32(d / time.Microsecond), nil
	}
	var err error
	if pb.BatchWindowUs, err = us("batch window", s.BatchWindow, MaxShapingDelay); err != nil {
		return nil, err
	}
	if pb.JitterUs, err = us("jitter", s.Jitter, MaxShapingDelay); err != nil {
		return nil, err
	}
	if pb.CoverIntervalUs, err = us("cover interval", s.CoverInterval, MaxCoverInterval); err != nil {
		return nil, err
	}
	if err := shaping.Check(pb); err != nil {
		return nil, err
	}
	return pb, nil
}

// ShapingSupport is what an adapter's shaping implements.
type ShapingSupport struct {
	Padding, Batching, Jitter, Cover bool
}

// AllShaping supports every setting.
var AllShaping = ShapingSupport{Padding: true, Batching: true, Jitter: true, Cover: true}

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
// bytes are no shaping. It rejects fields it doesn't know
// (ErrUnsupportedShaping), so a node too old for a setting refuses the link
// instead of ignoring the setting.
func ParseShaping(b []byte) (Shaping, error) {
	var s Shaping
	if len(b) == 0 {
		return s, nil
	}
	pb, err := shaping.Decode(b)
	if err != nil {
		return s, err
	}
	switch p := pb.GetPadding().(type) {
	case *transportv1.Shaping_Buckets:
		s.Padding.Mode = PadToBuckets
		for i, size := range p.Buckets.GetSizes() {
			s.Padding.Buckets[i] = uint16(size)
		}
	case *transportv1.Shaping_Random:
		s.Padding = Padding{Mode: PadRandom, Min: uint16(p.Random.GetMin()), Max: uint16(p.Random.GetMax())}
	}
	s.BatchWindow = time.Duration(pb.GetBatchWindowUs()) * time.Microsecond
	s.Jitter = time.Duration(pb.GetJitterUs()) * time.Microsecond
	s.CoverInterval = time.Duration(pb.GetCoverIntervalUs()) * time.Microsecond
	return s, nil
}

// Marshal encodes s as the map carries it, what the controller writes and
// ParseShaping reads, or says why s is invalid. No shaping is empty.
func (s Shaping) Marshal() ([]byte, error) {
	pb, err := s.message()
	if err != nil || s.IsZero() {
		return nil, err
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(pb)
	if err != nil {
		return nil, fmt.Errorf("transport: encode shaping: %w", err)
	}
	return b, nil
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

// SendReporter is a Link or Listener that reports what it sent. The engine
// and telemetry find it by type assertion; adapters that shape implement
// it.
type SendReporter interface {
	Sent() SendStats
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
