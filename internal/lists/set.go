package lists

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
)

// span is an inclusive address range of one family.
type span struct{ first, last u128 }

func cmpSpan(a, b span) int {
	switch {
	case a.first.less(b.first):
		return -1
	case b.first.less(a.first):
		return 1
	case a.last.less(b.last):
		return -1
	case b.last.less(a.last):
		return 1
	}
	return 0
}

// Builder collects prefixes and ranges, in any order and overlapping freely;
// [Builder.Build] aggregates them into a [Set]. The zero Builder is empty and
// ready to use.
type Builder struct {
	spans   [2][]span
	input   [2]int
	skipped int
}

// ErrInvalidPrefix is an address or prefix a list can't hold: invalid, a
// range end with a zone, or a range whose ends are of different families or
// out of order.
var ErrInvalidPrefix = errors.New("lists: invalid prefix")

// ErrMappedIPv6 is an IPv6 entry overlapping ::ffff:0:0/96, the IPv4-mapped
// addresses. Lists hold IPv4 only as IPv4, so one IPv6 entry (::/0, or
// ::ffff:0:0/96 itself) can never put all of IPv4 into a list, and
// [Set.Contains] can look a mapped address up as IPv4 without ambiguity.
var ErrMappedIPv6 = errors.New("lists: IPv6 entry overlaps the IPv4-mapped range ::ffff:0:0/96")

// mapped is ::ffff:0:0/96.
var mapped = span{u128{0, 0xffff << 32}, u128{0, 0xffff<<32 | 0xffffffff}}

func overlapsMapped(s span) bool { return !s.last.less(mapped.first) && !mapped.last.less(s.first) }

// AddPrefix adds p; host bits are ignored. An IPv6 prefix stays IPv6, even
// in IPv4-mapped notation, so one overlapping ::ffff:0:0/96 is refused with
// [ErrMappedIPv6].
func (b *Builder) AddPrefix(p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("%w: %v", ErrInvalidPrefix, p)
	}
	f, v := split(p.Addr())
	m := lowMask(f.width() - p.Bits())
	first := v.andNot(m)
	if f == fam6 && overlapsMapped(span{first, first.or(m)}) {
		return fmt.Errorf("%w: %v", ErrMappedIPv6, p)
	}
	b.spans[f] = append(b.spans[f], span{first, first.or(m)})
	b.input[f]++
	return nil
}

// AddRange adds every address from first to last inclusive. As in
// [Builder.AddPrefix], IPv6 stays IPv6 and may not overlap ::ffff:0:0/96.
func (b *Builder) AddRange(first, last netip.Addr) error {
	if !first.IsValid() || !last.IsValid() || first.Zone() != "" || last.Zone() != "" {
		return fmt.Errorf("%w: range %v-%v", ErrInvalidPrefix, first, last)
	}
	f1, v1 := split(first)
	f2, v2 := split(last)
	if f1 != f2 || v2.less(v1) {
		return fmt.Errorf("%w: range %v-%v", ErrInvalidPrefix, first, last)
	}
	if f1 == fam6 && overlapsMapped(span{v1, v2}) {
		return fmt.Errorf("%w: range %v-%v", ErrMappedIPv6, first, last)
	}
	b.spans[f1] = append(b.spans[f1], span{v1, v2})
	b.input[f1]++
	return nil
}

// AddSet adds every address of s; it counts in [Stats] as its prefixes.
func (b *Builder) AddSet(s *Set) {
	if s == nil {
		return
	}
	for f := range b.spans {
		b.spans[f] = append(b.spans[f], s.spans[f]...)
		for _, sp := range s.spans[f] {
			b.input[f] += countPrefixes(family(f), sp)
		}
	}
}

// Stats compares a list as imported with the aggregated set.
type Stats struct {
	// Added4 and Added6 count what was added: prefixes and ranges, one
	// each.
	Added4, Added6 int
	// Prefixes4 and Prefixes6 count the aggregated set's prefixes.
	Prefixes4, Prefixes6 int
	// Addresses4 counts the IPv4 addresses covered.
	Addresses4 uint64
	// Skipped counts entries an importer left out because they overlap
	// ::ffff:0:0/96 ([ErrMappedIPv6]).
	Skipped int
}

// Build aggregates everything added so far: overlapping and adjacent ranges
// merge, so the set is the unique minimal list of prefixes covering the
// same addresses. The Builder stays usable.
func (b *Builder) Build() (*Set, Stats) {
	s := &Set{}
	for f := range b.spans {
		s.spans[f] = merge(family(f), b.spans[f])
	}
	st := Stats{Added4: b.input[fam4], Added6: b.input[fam6], Skipped: b.skipped}
	for _, sp := range s.spans[fam4] {
		st.Prefixes4 += countPrefixes(fam4, sp)
		st.Addresses4 += sp.last.sub(sp.first).lo + 1
	}
	for _, sp := range s.spans[fam6] {
		st.Prefixes6 += countPrefixes(fam6, sp)
	}
	return s, st
}

func merge(f family, in []span) []span {
	spans := slices.Clone(in)
	slices.SortFunc(spans, cmpSpan)
	top := lowMask(f.width())
	out := spans[:0]
	for _, s := range spans {
		if n := len(out); n > 0 {
			cur := &out[n-1]
			// Overlapping or adjacent; nothing follows the top address.
			if cur.last == top || !cur.last.addOne().less(s.first) {
				if cur.last.less(s.last) {
					cur.last = s.last
				}
				continue
			}
		}
		out = append(out, s)
	}
	return slices.Clip(out)
}

// eachPrefix calls fn with the minimal prefixes covering s, in order: at each
// step the largest aligned block that starts at the current address and
// stays inside s.
func eachPrefix(f family, s span, fn func(first u128, bits int)) {
	w := f.width()
	a := s.first
	for {
		k := min(a.trailingZeros(), w)
		for k > 0 && s.last.less(a.or(lowMask(k))) {
			k--
		}
		last := a.or(lowMask(k))
		fn(a, w-k)
		if last == s.last {
			return
		}
		a = last.addOne()
	}
}

func countPrefixes(f family, s span) int {
	n := 0
	eachPrefix(f, s, func(u128, int) { n++ })
	return n
}

// Set is an aggregated, immutable set of IPv4 and IPv6 addresses: what a
// GeoIP list holds. Make one with [Builder.Build] or [Decode]; a nil *Set is
// empty.
type Set struct {
	// Sorted, disjoint and never adjacent, so a lookup is one binary search
	// and the set has exactly one representation.
	spans [2][]span
}

// Contains reports whether a is in the set; zones are ignored. An
// IPv4-mapped address (::ffff:a.b.c.d) is looked up as the IPv4 address it
// maps: a set holds no IPv6 inside ::ffff:0:0/96, so that is the only lookup
// that can match.
func (s *Set) Contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	f, v := fromAddr(a.WithZone(""))
	spans := s.spans[f]
	i := sort.Search(len(spans), func(i int) bool { return !spans[i].last.less(v) })
	return i < len(spans) && !v.less(spans[i].first)
}

// Prefixes returns the set as its minimal list of prefixes, IPv4 first, each
// family in address order. No two of them overlap or could merge into one.
func (s *Set) Prefixes() []netip.Prefix {
	if s == nil {
		return nil
	}
	var out []netip.Prefix
	for f := range s.spans {
		for _, sp := range s.spans[f] {
			eachPrefix(family(f), sp, func(first u128, bits int) {
				out = append(out, netip.PrefixFrom(toAddr(family(f), first), bits))
			})
		}
	}
	return out
}

// Range is an inclusive address range of one family.
type Range struct{ First, Last netip.Addr }

// Ranges returns the set as its ranges, IPv4 first, each family in address
// order: disjoint and never adjacent, so fewer than its prefixes (what an
// interval set in a firewall wants).
func (s *Set) Ranges() []Range {
	if s == nil {
		return nil
	}
	var out []Range
	for f := range s.spans {
		for _, sp := range s.spans[f] {
			out = append(out, Range{toAddr(family(f), sp.first), toAddr(family(f), sp.last)})
		}
	}
	return out
}

// Minus returns the addresses of s that are not in t.
func (s *Set) Minus(t *Set) *Set {
	out := &Set{}
	if s == nil {
		return out
	}
	for f := range s.spans {
		var cut []span
		if t != nil {
			cut = t.spans[f]
		}
		j := 0
		for _, cur := range s.spans[f] {
			for j < len(cut) && cut[j].last.less(cur.first) {
				j++
			}
			// cut[k] overlaps what is left of cur until one starts past it.
			keep := true
			for k := j; k < len(cut) && !cur.last.less(cut[k].first); k++ {
				if cur.first.less(cut[k].first) {
					out.spans[f] = append(out.spans[f], span{cur.first, cut[k].first.sub(u128{0, 1})})
				}
				if !cut[k].last.less(cur.last) {
					keep = false
					break
				}
				cur.first = cut[k].last.addOne()
			}
			if keep {
				out.spans[f] = append(out.spans[f], cur)
			}
		}
	}
	return out
}

// Intersect returns the addresses in both s and t.
func (s *Set) Intersect(t *Set) *Set { return s.Minus(s.Minus(t)) }

// IsEmpty reports whether s holds no address.
func (s *Set) IsEmpty() bool {
	return s == nil || len(s.spans[fam4]) == 0 && len(s.spans[fam6]) == 0
}

// Equal reports whether s and t hold the same addresses.
func (s *Set) Equal(t *Set) bool {
	var a, b [2][]span
	if s != nil {
		a = s.spans
	}
	if t != nil {
		b = t.spans
	}
	return slices.Equal(a[fam4], b[fam4]) && slices.Equal(a[fam6], b[fam6])
}
