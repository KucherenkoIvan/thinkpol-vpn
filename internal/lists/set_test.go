package lists

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

func build(t testing.TB, prefixes ...string) *Set {
	t.Helper()
	var b Builder
	for _, p := range prefixes {
		if err := b.AddPrefix(pfx(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := b.Build()
	return s
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// naive is the reference: an address is in the list if any input prefix
// contains it.
type naive []netip.Prefix

func (n naive) contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range n {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// randomIn returns a random address inside p.
func randomIn(r *rand.Rand, p netip.Prefix) netip.Addr {
	a := randAddr(r, p.Addr().Is6())
	for i := range p.Bits() {
		if p.Addr().AsSlice()[i/8]&(0x80>>(i%8)) != a.AsSlice()[i/8]&(0x80>>(i%8)) {
			a = flipBit(a, i)
		}
	}
	return a
}

func flipBit(a netip.Addr, i int) netip.Addr {
	b := a.AsSlice()
	b[i/8] ^= 0x80 >> (i % 8)
	out, _ := netip.AddrFromSlice(b)
	return out
}

// randPrefix returns a prefix inside base, longer than base by 0..extra bits.
func randPrefix(r *rand.Rand, base netip.Prefix, extra int) netip.Prefix {
	b := base.Addr().AsSlice()
	for i := base.Bits(); i < len(b)*8; i++ {
		if r.IntN(2) == 1 {
			b[i/8] |= 0x80 >> (i % 8)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return netip.PrefixFrom(a, base.Bits()+r.IntN(extra+1)).Masked()
}

// checkCanonical asserts what Set.Prefixes promises: per family ascending,
// disjoint, and no two neighbours that are the halves of one prefix.
func checkCanonical(t *testing.T, ps []netip.Prefix) {
	t.Helper()
	for i := 1; i < len(ps); i++ {
		a, b := ps[i-1], ps[i]
		if a.Addr().Is4() != b.Addr().Is4() {
			if !a.Addr().Is4() {
				t.Fatalf("IPv6 %v before IPv4 %v", a, b)
			}
			continue
		}
		if a.Overlaps(b) || b.Addr().Less(a.Addr()) {
			t.Fatalf("%v and %v out of order or overlapping", a, b)
		}
		if a.Bits() == b.Bits() && a.Bits() > 0 {
			pa, _ := a.Addr().Prefix(a.Bits() - 1)
			pb, _ := b.Addr().Prefix(b.Bits() - 1)
			if pa == pb {
				t.Fatalf("%v and %v should have merged into %v", a, b, pa)
			}
		}
	}
}

// TestAggregationExhaustive checks every address of a small universe, so the
// aggregated set holds exactly the input's addresses, for both families.
func TestAggregationExhaustive(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for _, base := range []netip.Prefix{pfx("10.0.0.0/22"), pfx("2001:db8::/118"), pfx("255.255.252.0/22"), pfx("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fc00/118")} {
		for range 300 {
			var in naive
			var b Builder
			for range 1 + r.IntN(40) {
				p := randPrefix(r, base, 10)
				in = append(in, p)
				if err := b.AddPrefix(p); err != nil {
					t.Fatal(err)
				}
			}
			s, st := b.Build()
			for a := base.Addr(); base.Contains(a); a = a.Next() {
				if got, want := s.Contains(a), in.contains(a); got != want {
					t.Fatalf("%v: Contains(%v) = %v, want %v", in, a, got, want)
				}
			}
			ps := s.Prefixes()
			checkCanonical(t, ps)
			if n := st.Prefixes4 + st.Prefixes6; n != len(ps) || st.Added4+st.Added6 != len(in) {
				t.Fatalf("stats %+v for %d in, %d out", st, len(in), len(ps))
			}
			// Aggregating the output again changes nothing.
			if again := build(t, strs(ps)...); !again.Equal(s) || !slices.Equal(again.Prefixes(), ps) {
				t.Fatalf("not idempotent: %v -> %v", ps, again.Prefixes())
			}
		}
	}
}

// TestLookupMatchesNaive compares Contains with a linear scan over random
// lists spanning the whole address space, probing each input prefix's edges
// and their neighbours.
func TestLookupMatchesNaive(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for range 50 {
		var in naive
		var b Builder
		for range 200 {
			p := netip.PrefixFrom(randAddr(r, false), 8+r.IntN(25)).Masked()
			if r.IntN(2) == 0 {
				p = netip.PrefixFrom(randAddr(r, true), 16+r.IntN(113)).Masked()
			}
			in = append(in, p)
			if err := b.AddPrefix(p); err != nil {
				t.Fatal(err)
			}
		}
		s, _ := b.Build()
		checkCanonical(t, s.Prefixes())
		var probes []netip.Addr
		for _, p := range in {
			first := p.Addr()
			last := netip.PrefixFrom(first, first.BitLen()).Addr()
			for i := p.Bits(); i < first.BitLen(); i++ {
				last = setBit(last, i)
			}
			probes = append(probes, first, last, first.Prev(), last.Next())
		}
		for range 1000 {
			probes = append(probes, randAddr(r, false), randAddr(r, true))
		}
		for _, a := range probes {
			if !a.IsValid() {
				continue
			}
			if got, want := s.Contains(a), in.contains(a); got != want {
				t.Fatalf("Contains(%v) = %v, want %v", a, got, want)
			}
		}
	}
}

func randAddr(r *rand.Rand, v6 bool) netip.Addr {
	if v6 {
		var b [16]byte
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return netip.AddrFrom16(b)
	}
	return netip.AddrFrom4([4]byte{byte(r.Uint32()), byte(r.Uint32()), byte(r.Uint32()), byte(r.Uint32())})
}

func setBit(a netip.Addr, i int) netip.Addr {
	b := a.AsSlice()
	b[i/8] |= 0x80 >> (i % 8)
	out, _ := netip.AddrFromSlice(b)
	return out
}

func TestRangesBecomeMinimalPrefixes(t *testing.T) {
	cases := []struct {
		first, last string
		want        []string
	}{
		{"1.0.0.0", "1.0.3.255", []string{"1.0.0.0/22"}},
		{"1.0.0.1", "1.0.0.6", []string{"1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6/32"}},
		{"0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
		{"255.255.255.254", "255.255.255.255", []string{"255.255.255.254/31"}},
		{"0.0.0.0", "0.0.0.0", []string{"0.0.0.0/32"}},
		{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"::/0"}},
		{"2000::", "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"2000::/16"}},
		{"::1", "::ffff:ffff:ffff:ffff", []string{"::1/128", "::2/127", "::4/126", "::8/125", "::10/124", "::20/123", "::40/122", "::80/121", "::100/120", "::200/119", "::400/118", "::800/117", "::1000/116", "::2000/115", "::4000/114", "::8000/113", "::1:0/112", "::2:0/111", "::4:0/110", "::8:0/109", "::10:0/108", "::20:0/107", "::40:0/106", "::80:0/105", "::100:0/104", "::200:0/103", "::400:0/102", "::800:0/101", "::1000:0/100", "::2000:0/99", "::4000:0/98", "::8000:0/97", "::1:0:0/96", "::2:0:0/95", "::4:0:0/94", "::8:0:0/93", "::10:0:0/92", "::20:0:0/91", "::40:0:0/90", "::80:0:0/89", "::100:0:0/88", "::200:0:0/87", "::400:0:0/86", "::800:0:0/85", "::1000:0:0/84", "::2000:0:0/83", "::4000:0:0/82", "::8000:0:0/81", "::1:0:0:0/80", "::2:0:0:0/79", "::4:0:0:0/78", "::8:0:0:0/77", "::10:0:0:0/76", "::20:0:0:0/75", "::40:0:0:0/74", "::80:0:0:0/73", "::100:0:0:0/72", "::200:0:0:0/71", "::400:0:0:0/70", "::800:0:0:0/69", "::1000:0:0:0/68", "::2000:0:0:0/67", "::4000:0:0:0/66", "::8000:0:0:0/65"}},
		{"1:2::ffff:ffff:ffff:ffff", "1:2:0:1::", []string{"1:2::ffff:ffff:ffff:ffff/128", "1:2:0:1::/128"}},
	}
	for _, c := range cases {
		var b Builder
		if err := b.AddRange(addr(c.first), addr(c.last)); err != nil {
			t.Fatal(err)
		}
		s, st := b.Build()
		if got := strs(s.Prefixes()); !slices.Equal(got, c.want) {
			t.Errorf("%s-%s: %v, want %v", c.first, c.last, got, c.want)
		}
		if st.Added4+st.Added6 != 1 || st.Prefixes4+st.Prefixes6 != len(c.want) {
			t.Errorf("%s-%s: stats %+v", c.first, c.last, st)
		}
	}
}

func TestMergesOverlappingAndAdjacent(t *testing.T) {
	var b Builder
	for _, p := range []string{"10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/24", "10.0.1.0/24", "10.0.0.7/32", "192.168.1.1/16", "2001:db8::/33", "2001:db8:8000::/33", "::ffff:172.16.0.0/108"} {
		if err := b.AddPrefix(pfx(p)); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.AddRange(addr("10.0.2.0"), addr("10.0.3.255")); err != nil {
		t.Fatal(err)
	}
	s, st := b.Build()
	want := []string{"10.0.0.0/22", "172.16.0.0/12", "192.168.0.0/16", "2001:db8::/32"}
	if got := strs(s.Prefixes()); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if st != (Stats{Added4: 8, Added6: 2, Prefixes4: 3, Prefixes6: 1, Addresses4: 1024 + 1<<20 + 1<<16}) {
		t.Fatalf("stats %+v", st)
	}

	// A set added to a builder is a union.
	var u Builder
	u.AddSet(s)
	u.AddSet(build(t, "10.0.4.0/22", "2001:db9::/32"))
	us, _ := u.Build()
	want = []string{"10.0.0.0/21", "172.16.0.0/12", "192.168.0.0/16", "2001:db8::/31"}
	if got := strs(us.Prefixes()); !slices.Equal(got, want) {
		t.Fatalf("union %v, want %v", got, want)
	}
}

func TestPrefixNormalization(t *testing.T) {
	cases := map[string]string{
		"10.1.2.3/8":             "10.0.0.0/8",
		"::ffff:10.1.2.3/104":    "10.0.0.0/8",
		"::ffff:10.1.2.3/128":    "10.1.2.3/32",
		"::ffff:0.0.0.0/96":      "0.0.0.0/0",
		"::ffff:0.0.0.0/95":      "::fffe:0:0/95",
		"2001:db8::1/32":         "2001:db8::/32",
		"0.0.0.0/0":              "0.0.0.0/0",
		"::/0":                   "::/0",
		"::/128":                 "::/128",
		"ffff:ffff::/16":         "ffff::/16",
		"255.255.255.255/32":     "255.255.255.255/32",
		"64:ff9b::1.2.3.4/96":    "64:ff9b::/96",
		"::ffff:1.2.3.4/120":     "1.2.3.0/24",
		"2001:db8::ffff:0:0/112": "2001:db8::ffff:0:0/112",
	}
	for in, want := range cases {
		if got := strs(build(t, in).Prefixes()); !slices.Equal(got, []string{want}) {
			t.Errorf("%s: %v, want %s", in, got, want)
		}
	}
}

func TestRejectsInvalidInput(t *testing.T) {
	var b Builder
	for _, p := range []netip.Prefix{{}, netip.PrefixFrom(addr("1.2.3.4"), 33)} {
		if err := b.AddPrefix(p); !errors.Is(err, ErrInvalidPrefix) {
			t.Errorf("AddPrefix(%v): %v", p, err)
		}
	}
	for _, r := range [][2]netip.Addr{
		{addr("1.2.3.4"), addr("1.2.3.3")},
		{addr("1.2.3.4"), addr("::1")},
		{addr("::2"), addr("::1")},
		{{}, addr("1.2.3.4")},
		{addr("fe80::1%eth0"), addr("fe80::2")},
	} {
		if err := b.AddRange(r[0], r[1]); !errors.Is(err, ErrInvalidPrefix) {
			t.Errorf("AddRange(%v, %v): %v", r[0], r[1], err)
		}
	}
	if s, st := b.Build(); len(s.Prefixes()) != 0 || st != (Stats{}) {
		t.Fatalf("rejected input was kept: %v %+v", s.Prefixes(), st)
	}
}

func TestContainsEdges(t *testing.T) {
	s := build(t, "10.0.0.0/8", "2001:db8::/32")
	for a, want := range map[string]bool{
		"10.0.0.0":          true,
		"10.255.255.255":    true,
		"9.255.255.255":     false,
		"11.0.0.0":          false,
		"::ffff:10.1.1.1":   true,
		"::a01:101":         false, // IPv4-compatible, not mapped: an IPv6 address
		"2001:db8::1%eth0":  true,
		"2001:db9::":        false,
		"2001:db7:ffff::":   false,
		"::":                false,
		"0.0.0.0":           false,
		"255.255.255.255":   false,
		"ffff::ffff:ffff:1": false,
	} {
		if got := s.Contains(addr(a)); got != want {
			t.Errorf("Contains(%s) = %v", a, got)
		}
	}
	if s.Contains(netip.Addr{}) {
		t.Error("invalid address contained")
	}
	var nilSet *Set
	if nilSet.Contains(addr("10.0.0.1")) || nilSet.Prefixes() != nil || !nilSet.Equal(&Set{}) || nilSet.Equal(s) {
		t.Error("nil set is not empty")
	}
	all := build(t, "0.0.0.0/0", "::/0")
	if !all.Contains(addr("0.0.0.0")) || !all.Contains(addr("255.255.255.255")) || !all.Contains(addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) {
		t.Error("full set misses an edge")
	}
}

// BenchmarkContains looks up in a set the size of the RU list (about 13k
// IPv4 and 10k IPv6 prefixes).
func BenchmarkContains(b *testing.B) {
	r := rand.New(rand.NewPCG(5, 6))
	var bl Builder
	for range 13000 {
		_ = bl.AddPrefix(netip.PrefixFrom(randAddr(r, false), 16+r.IntN(9)).Masked())
	}
	for range 10000 {
		_ = bl.AddPrefix(netip.PrefixFrom(randomIn(r, pfx("2000::/3")), 20+r.IntN(29)).Masked())
	}
	s, st := bl.Build()
	b.Logf("%d IPv4 and %d IPv6 prefixes", st.Prefixes4, st.Prefixes6)
	probes := make([]netip.Addr, 1024)
	for i := range probes {
		probes[i] = randAddr(r, false)
		if i%2 == 1 {
			probes[i] = randomIn(r, pfx("2000::/3"))
		}
	}
	b.ResetTimer()
	for i := range b.N {
		s.Contains(probes[i%len(probes)])
	}
}

func TestAddNilSet(t *testing.T) {
	var b Builder
	b.AddSet(nil)
	if s, st := b.Build(); len(s.Prefixes()) != 0 || st != (Stats{}) {
		t.Fatal("nil set added something")
	}
}
