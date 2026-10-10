package shaping_test

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/shaping"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

func TestDecode(t *testing.T) {
	ok := []*transportv1.Shaping{
		{},
		{Padding: &transportv1.Shaping_Buckets{Buckets: &transportv1.PadToBuckets{Sizes: []uint32{128, 1452}}}},
		{Padding: &transportv1.Shaping_Random{Random: &transportv1.PadRandom{Min: 0, Max: 64}}, JitterUs: 1000, CoverIntervalUs: 10_000},
	}
	for _, pb := range ok {
		b, err := proto.Marshal(pb)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := shaping.Decode(b); err != nil || !proto.Equal(got, pb) {
			t.Errorf("%v: %v, %v", pb, got, err)
		}
	}
	bad := map[string]*transportv1.Shaping{
		"empty buckets":   {Padding: &transportv1.Shaping_Buckets{Buckets: &transportv1.PadToBuckets{}}},
		"random of 0":     {Padding: &transportv1.Shaping_Random{Random: &transportv1.PadRandom{}}},
		"batch over 1 s":  {BatchWindowUs: 1_000_001},
		"cover too often": {CoverIntervalUs: 9_999},
		"cover too rare":  {CoverIntervalUs: 3_600_000_001},
	}
	for name, pb := range bad {
		if err := shaping.Check(pb); !errors.Is(err, shaping.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	unknown := append([]byte(nil), 0xf8, 0x06, 0x01) // field 111, varint 1
	if _, err := shaping.Decode(unknown); !errors.Is(err, shaping.ErrUnsupported) {
		t.Errorf("unknown field: %v, want ErrUnsupported", err)
	}
}
