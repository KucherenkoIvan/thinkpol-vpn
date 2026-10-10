package transport_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

func TestShapingRoundTrip(t *testing.T) {
	for _, s := range []transport.Shaping{
		{},
		{Padding: transport.Buckets(128, 256, 1452)},
		{Padding: transport.Buckets(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 65535)},
		{Padding: transport.Padding{Mode: transport.PadRandom, Min: 0, Max: 1}},
		{Padding: transport.Padding{Mode: transport.PadRandom, Min: 7, Max: 7}},
		{BatchWindow: 1500 * time.Microsecond, Jitter: time.Second, CoverInterval: time.Hour},
	} {
		b, err := s.Marshal()
		if err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
		if s.IsZero() != (len(b) == 0) {
			t.Errorf("%+v encodes to %d bytes", s, len(b))
		}
		got, err := transport.ParseShaping(b)
		if err != nil || got != s {
			t.Errorf("%+v: round trip gave %+v, %v", s, got, err)
		}
	}
}

func TestParseShapingRefusesWhatItDoesNotKnow(t *testing.T) {
	buckets, err := transport.Shaping{Padding: transport.Buckets(256)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	unknownTop := protowire.AppendVarint(protowire.AppendTag(append([]byte(nil), buckets...), 99, protowire.VarintType), 1)
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.VarintType)
	inner = protowire.AppendVarint(inner, 256)
	inner = protowire.AppendTag(inner, 9, protowire.VarintType)
	inner = protowire.AppendVarint(inner, 1)
	unknownNested := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), inner)
	for name, b := range map[string][]byte{"top level": unknownTop, "inside buckets": unknownNested} {
		if _, err := transport.ParseShaping(b); !errors.Is(err, transport.ErrUnsupportedShaping) {
			t.Errorf("unknown field %s: %v, want ErrUnsupportedShaping", name, err)
		}
	}

	sizes := func(sizes ...uint64) []byte {
		var inner []byte
		for _, s := range sizes {
			inner = protowire.AppendTag(inner, 1, protowire.VarintType)
			inner = protowire.AppendVarint(inner, s)
		}
		return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), inner)
	}
	random := func(lo, hi uint64) []byte {
		var inner []byte
		inner = protowire.AppendVarint(protowire.AppendTag(inner, 1, protowire.VarintType), lo)
		inner = protowire.AppendVarint(protowire.AppendTag(inner, 2, protowire.VarintType), hi)
		return protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), inner)
	}
	for name, b := range map[string][]byte{
		"garbage":           {0xff, 0xff},
		"no buckets":        sizes(),
		"zero bucket":       sizes(0, 10),
		"descending":        sizes(512, 256),
		"repeated":          sizes(256, 256),
		"bucket over 65535": sizes(70000),
		"17 buckets":        sizes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17),
		"random max 0":      random(0, 0),
		"random min > max":  random(5, 4),
		"random over 65535": random(0, 70000),
		"jitter of 2s":      protowire.AppendVarint(protowire.AppendTag(nil, 4, protowire.VarintType), 2_000_000),
		"cover every 1ms":   protowire.AppendVarint(protowire.AppendTag(nil, 5, protowire.VarintType), 1000),
	} {
		if _, err := transport.ParseShaping(b); !errors.Is(err, transport.ErrInvalidShaping) {
			t.Errorf("%s: %v, want ErrInvalidShaping", name, err)
		}
	}
}

func TestMarshalRefusesInvalidShaping(t *testing.T) {
	gap := transport.Buckets(100, 200)
	gap.Buckets[1], gap.Buckets[2] = 0, 200
	for name, s := range map[string]transport.Shaping{
		"descending buckets":   {Padding: transport.Buckets(200, 100)},
		"a gap in the buckets": {Padding: gap},
		"buckets without mode": {Padding: transport.Padding{Buckets: transport.Buckets(1).Buckets}},
		"random of nothing":    {Padding: transport.Padding{Mode: transport.PadRandom}},
		"unknown mode":         {Padding: transport.Padding{Mode: 7}},
		"negative jitter":      {Jitter: -time.Microsecond},
		"nanosecond batching":  {BatchWindow: time.Nanosecond},
		"cover every 1 ms":     {CoverInterval: time.Millisecond},
		"cover every 2 h":      {CoverInterval: 2 * time.Hour},
	} {
		if b, err := s.Marshal(); !errors.Is(err, transport.ErrInvalidShaping) || b != nil {
			t.Errorf("%s: %d bytes, %v; want ErrInvalidShaping", name, len(b), err)
		}
	}
}

func TestMaxDelay(t *testing.T) {
	s := transport.Shaping{BatchWindow: 2 * time.Millisecond, Jitter: 3 * time.Millisecond}
	if s.MaxDelay() != 5*time.Millisecond || (transport.Shaping{}).MaxDelay() != 0 {
		t.Errorf("MaxDelay %v", s.MaxDelay())
	}
}

func TestPaddingSize(t *testing.T) {
	b := transport.Buckets(100, 200, 300)
	for size, want := range map[int]int{1: 100, 100: 100, 101: 200, 300: 300, 301: 301, 5000: 5000} {
		if got := b.Size(size); got != want {
			t.Errorf("buckets: %d pads to %d, want %d", size, got, want)
		}
	}
	r := transport.Padding{Mode: transport.PadRandom, Min: 3, Max: 6}
	seen := map[int]bool{}
	for range 1000 {
		got := r.Size(10)
		if got < 13 || got > 16 {
			t.Fatalf("random: 10 pads to %d, want 13 to 16", got)
		}
		seen[got] = true
	}
	if len(seen) != 4 {
		t.Errorf("random padding took %d of 4 values", len(seen))
	}
	if (transport.Padding{}).Size(42) != 42 {
		t.Error("no padding padded")
	}
}

func TestMaxPacket(t *testing.T) {
	tr := udp.New(udp.Options{})
	for _, tc := range []struct {
		name    string
		shaping transport.Shaping
		unit    int
		want    int
	}{
		{"none", transport.Shaping{}, 1452, 1452 - udp.Overhead},
		{"buckets all below", transport.Shaping{Padding: transport.Buckets(128, 1400)}, 1452, 1452 - udp.Overhead},
		{"bucket at the unit", transport.Shaping{Padding: transport.Buckets(128, 1452)}, 1452, 1452 - udp.Overhead},
		{"bucket above the unit", transport.Shaping{Padding: transport.Buckets(128, 1024, 1500)}, 1452, 1024 - udp.Overhead},
		{"every bucket above", transport.Shaping{Padding: transport.Buckets(1500)}, 1452, 0},
		{"random", transport.Shaping{Padding: transport.Padding{Mode: transport.PadRandom, Max: 100}}, 1452, 1452 - udp.Overhead - 100},
		{"tiny unit", transport.Shaping{}, 50, 0},
		{"jumbo unit", transport.Shaping{}, 65000, transport.MaxPacketSize},
	} {
		got := transport.MaxPacket(tr, tc.shaping, tc.unit)
		if got != tc.want {
			t.Errorf("%s: MaxPacket %d, want %d", tc.name, got, tc.want)
		}
		if p := tc.shaping.Padding; got > 0 && p.Mode == transport.PadToBuckets {
			for n := 1; n <= got; n++ {
				if size := p.Size(n + tr.Overhead(tc.shaping)); size > tc.unit {
					t.Fatalf("%s: a %d-byte packet pads to %d > %d", tc.name, n, size, tc.unit)
				}
			}
		}
	}
}

func TestShapingSupport(t *testing.T) {
	padOnly := transport.ShapingSupport{Padding: true}
	if err := padOnly.Check(transport.Shaping{Padding: transport.Buckets(512)}); err != nil {
		t.Errorf("padding refused: %v", err)
	}
	for _, s := range []transport.Shaping{
		{BatchWindow: time.Millisecond},
		{Jitter: time.Millisecond},
		{CoverInterval: time.Second},
	} {
		if err := padOnly.Check(s); !errors.Is(err, transport.ErrUnsupportedShaping) {
			t.Errorf("%+v: %v, want ErrUnsupportedShaping", s, err)
		}
	}
	all := transport.ShapingSupport{Padding: true, Batching: true, Jitter: true, Cover: true}
	if err := all.Check(transport.Shaping{Padding: transport.Buckets(2, 1)}); !errors.Is(err, transport.ErrInvalidShaping) {
		t.Errorf("descending buckets: %v, want ErrInvalidShaping", err)
	}
	if err := all.Check(transport.Shaping{Jitter: 1500 * time.Nanosecond}); !errors.Is(err, transport.ErrInvalidShaping) {
		t.Errorf("jitter not in whole microseconds: %v, want ErrInvalidShaping", err)
	}
}

func TestSendStats(t *testing.T) {
	var m transport.SendMeter
	m.Sent(1, 100, 50, 224)
	m.Sent(1, 100, 0, 174)
	s := m.Stats()
	if s != (transport.SendStats{Units: 2, Packets: 2, PacketBytes: 200, PaddingBytes: 50, WireBytes: 398}) {
		t.Fatalf("stats %+v", s)
	}
	if got := s.Overhead(); got < 0.989 || got > 0.991 {
		t.Errorf("overhead %v, want 0.99", got)
	}
	if (transport.SendStats{}).Overhead() != 0 {
		t.Error("overhead of nothing sent")
	}
}
