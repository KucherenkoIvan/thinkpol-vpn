package shaping

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

var (
	// ErrInvalid marks shaping that makes no sense on any transport.
	ErrInvalid = errors.New("invalid shaping")
	// ErrUnsupported marks shaping a reader can't honour: here, fields it
	// doesn't know.
	ErrUnsupported = errors.New("shaping not supported")
)

// Limits every transport shares; adapters may be stricter.
const (
	MaxBuckets = 16
	// MaxUnit is the largest unit size a bucket or random padding names.
	MaxUnit = 0xffff
	// MaxDelay bounds the batching window and the jitter: more would stall
	// the TCP connections inside the tunnel.
	MaxDelay         = time.Second
	MinCoverInterval = 10 * time.Millisecond
	MaxCoverInterval = time.Hour
)

// Decode reads an encoded message strictly: unknown fields anywhere are
// ErrUnsupported, so a node too old for a setting refuses the link instead
// of ignoring it; then Check. Empty bytes are no shaping.
func Decode(b []byte) (*transportv1.Shaping, error) {
	var pb transportv1.Shaping
	if err := proto.Unmarshal(b, &pb); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if hasUnknown(pb.ProtoReflect()) {
		return nil, fmt.Errorf("%w: fields this node doesn't know", ErrUnsupported)
	}
	if err := Check(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}

// Check applies the rules to a message; errors match ErrInvalid.
func Check(pb *transportv1.Shaping) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
	}
	switch p := pb.GetPadding().(type) {
	case *transportv1.Shaping_Buckets:
		sizes := p.Buckets.GetSizes()
		if len(sizes) == 0 || len(sizes) > MaxBuckets {
			return invalid("%d buckets, want 1 to %d", len(sizes), MaxBuckets)
		}
		for i, size := range sizes {
			if size == 0 || size > MaxUnit {
				return invalid("a bucket of %d bytes", size)
			}
			if i > 0 && size <= sizes[i-1] {
				return invalid("buckets not strictly ascending: %d after %d", size, sizes[i-1])
			}
		}
	case *transportv1.Shaping_Random:
		lo, hi := p.Random.GetMin(), p.Random.GetMax()
		if hi == 0 || lo > hi || hi > MaxUnit {
			return invalid("random padding of [%d, %d] bytes", lo, hi)
		}
	case nil:
	default:
		return invalid("padding %T", p)
	}
	us := func(d time.Duration) uint32 { return uint32(d / time.Microsecond) }
	if b := pb.GetBatchWindowUs(); b > us(MaxDelay) {
		return invalid("batch window of %d µs, at most %v", b, MaxDelay)
	}
	if j := pb.GetJitterUs(); j > us(MaxDelay) {
		return invalid("jitter of %d µs, at most %v", j, MaxDelay)
	}
	if c := pb.GetCoverIntervalUs(); c != 0 && (c < us(MinCoverInterval) || c > us(MaxCoverInterval)) {
		return invalid("cover interval of %d µs, want %v to %v", c, MinCoverInterval, MaxCoverInterval)
	}
	return nil
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
