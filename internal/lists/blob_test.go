package lists

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBlobGolden pins the format: a change here changes every list's hash
// in every deployed map.
func TestBlobGolden(t *testing.T) {
	s := build(t, "192.168.1.0/24", "fe80::/10", "10.0.0.0/8", "2001:db8::/32", "1.2.3.4/32")
	const want = "54504950" + "01" +
		"03" + "2001020304" + "080a" + "18c0a801" +
		"02" + "2020010db8" + "0afe80"
	if got := hex.EncodeToString(s.Blob()); got != want {
		t.Fatalf("blob %s, want %s", got, want)
	}
	if got := hex.EncodeToString((&Set{}).Blob()); got != "54504950010000" {
		t.Fatalf("empty blob %s", got)
	}
	var nilSet *Set
	if got := hex.EncodeToString(nilSet.Blob()); got != "54504950010000" {
		t.Fatalf("nil blob %s", got)
	}
}

// TestBlobDeterministic: the hash depends only on the addresses, not on the
// order, overlap or shape of the input.
func TestBlobDeterministic(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	for range 100 {
		var in []netip.Prefix
		for range 1 + r.IntN(300) {
			p := netip.PrefixFrom(randAddr(r, false), 8+r.IntN(25)).Masked()
			if r.IntN(2) == 0 {
				p = netip.PrefixFrom(randAddr(r, true), 16+r.IntN(113)).Masked()
			}
			in = append(in, p)
		}
		var b1, b2, b3 Builder
		for _, p := range in {
			_ = b1.AddPrefix(p)
		}
		// Shuffled, with duplicates.
		for _, i := range r.Perm(len(in)) {
			_ = b2.AddPrefix(in[i])
			if r.IntN(4) == 0 {
				_ = b2.AddPrefix(in[i])
			}
		}
		s1, _ := b1.Build()
		s2, _ := b2.Build()
		// The same addresses as ranges, one per aggregated prefix.
		for _, p := range s1.Prefixes() {
			last := p.Addr()
			for i := p.Bits(); i < last.BitLen(); i++ {
				last = setBit(last, i)
			}
			if err := b3.AddRange(p.Addr(), last); err != nil {
				t.Fatal(err)
			}
		}
		s3, _ := b3.Build()
		h1, h2, h3 := sha256.Sum256(s1.Blob()), sha256.Sum256(s2.Blob()), sha256.Sum256(s3.Blob())
		if h1 != h2 || h1 != h3 || !bytes.Equal(s1.Blob(), s1.Blob()) {
			t.Fatalf("hashes differ for the same addresses: %x %x %x", h1, h2, h3)
		}
		// And the blob round-trips.
		d, err := Decode(s1.Blob())
		if err != nil || !d.Equal(s1) || !bytes.Equal(d.Blob(), s1.Blob()) {
			t.Fatalf("round trip: %v", err)
		}
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	const head = "5450495001"
	cases := map[string]string{
		"empty":                   "",
		"bad magic":               "5450495801" + "0000",
		"no version":              "54504950",
		"truncated count":         head,
		"truncated v6 count":      head + "00",
		"trailing byte":           head + "000000",
		"count beyond the end":    head + "05" + "080a" + "00",
		"truncated prefix":        head + "01" + "18c0a8" + "00",
		"v4 prefix too long":      head + "01" + "2101020304ff" + "00",
		"v6 prefix too long":      head + "00" + "01" + "81" + "00000000000000000000000000000000" + "00",
		"host bits set":           head + "01" + "090aff" + "00",
		"host bits in last byte":  head + "01" + "0c0a01" + "00",
		"unsorted":                head + "02" + "080b" + "080a" + "00",
		"overlapping":             head + "02" + "080a" + "100a01" + "00",
		"duplicate":               head + "02" + "080a" + "080a" + "00",
		"mergeable halves":        head + "02" + "080a" + "080b" + "00",
		"mergeable /9 halves":     head + "02" + "090a00" + "090a80" + "00",
		"overlong count varint":   head + "8000" + "00",
		"v6 inside ::ffff:0:0/96": head + "00" + "01" + mappedPrefix,
		"v6 /0":                   head + "00" + "01" + "00",
		"v6 covering mapped":      head + "00" + "01" + "40" + "0000000000000000",
		"count over the bound":    head + "03" + "0000" + "00",
	}
	for name, h := range cases {
		if _, err := Decode(unhex(t, h)); !errors.Is(err, ErrMalformedBlob) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Decode(unhex(t, "5450495002"+"0000")); !errors.Is(err, ErrUnsupportedBlob) {
		t.Errorf("version 2: %v", err)
	}
	// Canonical neighbours of the cases above do decode.
	for _, h := range []string{head + "0000", head + "02" + "090a00" + "080b" + "00", head + "01" + "0c0a00" + "00", head + "00" + "01" + "80" + "00000000000000000000000000000001"} {
		if _, err := Decode(unhex(t, h)); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}

// mappedPrefix is ::ffff:1.2.0.0/112 in the blob's prefix encoding.
const mappedPrefix = "70" + "00000000000000000000ffff0102"

func FuzzDecode(f *testing.F) {
	f.Add(build(f, "192.168.1.0/24", "fe80::/10", "10.0.0.0/8", "2001:db8::/32", "1.2.3.4/32").Blob())
	f.Add((&Set{}).Blob())
	f.Add(build(f, "0.0.0.0/0", "8000::/1").Blob())
	f.Add(unhex(f, "5450495001"+"00"+"01"+mappedPrefix))
	f.Add(unhex(f, "5450495001"+"01"+"00"+"01"+"00"))
	f.Fuzz(func(t *testing.T, blob []byte) {
		s, err := Decode(blob)
		if err != nil {
			return
		}
		if !bytes.Equal(s.Blob(), blob) {
			t.Fatalf("accepted a non-canonical blob %x", blob)
		}
		for _, p := range s.Prefixes() {
			if !s.Contains(p.Addr()) {
				t.Fatalf("%v not contained", p)
			}
			if p.Addr().Is6() && p.Overlaps(netip.MustParsePrefix("::ffff:0:0/96")) {
				t.Fatalf("accepted %v, inside the IPv4-mapped range", p)
			}
		}
	})
}
