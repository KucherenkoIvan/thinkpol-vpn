package lists

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// u128 is an address as a number: IPv6 uses all 128 bits, IPv4 the low 32.
// One code path serves both families; only the width differs.
type u128 struct{ hi, lo uint64 }

const (
	width4 = 32
	width6 = 128
)

// family indexes per-family slices: 0 is IPv4, 1 is IPv6.
type family int

const (
	fam4 family = iota
	fam6
)

func (f family) width() int {
	if f == fam4 {
		return width4
	}
	return width6
}

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

func (a u128) or(b u128) u128 { return u128{a.hi | b.hi, a.lo | b.lo} }

func (a u128) andNot(b u128) u128 { return u128{a.hi &^ b.hi, a.lo &^ b.lo} }

func (a u128) addOne() u128 {
	lo, carry := bits.Add64(a.lo, 1, 0)
	return u128{a.hi + carry, lo}
}

func (a u128) sub(b u128) u128 {
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	return u128{a.hi - b.hi - borrow, lo}
}

func (a u128) trailingZeros() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo)
	}
	return 64 + bits.TrailingZeros64(a.hi) // 128 for zero
}

// lowMask has the low k bits set, 0 <= k <= 128.
func lowMask(k int) u128 {
	switch {
	case k >= 128:
		return u128{^uint64(0), ^uint64(0)}
	case k >= 64:
		return u128{uint64(1)<<(k-64) - 1, ^uint64(0)}
	default:
		return u128{0, uint64(1)<<k - 1}
	}
}

// fromAddr splits a valid address without a zone into its family and value;
// IPv4-mapped IPv6 addresses count as IPv4.
func fromAddr(a netip.Addr) (family, u128) {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fam4, u128{0, uint64(binary.BigEndian.Uint32(b[:]))}
	}
	return fam6, from16(a)
}

func from16(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func toAddr(f family, v u128) netip.Addr {
	if f == fam4 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v.lo))
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], v.hi)
	binary.BigEndian.PutUint64(b[8:], v.lo)
	return netip.AddrFrom16(b)
}
