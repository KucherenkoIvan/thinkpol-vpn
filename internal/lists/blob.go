package lists

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// The blob is a Set's one canonical encoding, so its SHA-256 names the set:
// the same addresses always give the same bytes, whatever the source, the
// order of the input or how it overlapped.
//
//	magic    "TPIP"
//	version  0x01
//	count4   uvarint, then count4 IPv4 prefixes
//	count6   uvarint, then count6 IPv6 prefixes
//
// A prefix is its length in bits (one byte) followed by the first
// ceil(bits/8) bytes of its address, host bits zero. Prefixes are the set's
// minimal list ([Set.Prefixes]): ascending, disjoint, no two mergeable. Not
// compressed: compressors' output can change between versions, the hash
// must not.
const (
	blobMagic   = "TPIP"
	blobVersion = 1
)

// ErrMalformedBlob is a blob that isn't a canonical encoding of a set.
var ErrMalformedBlob = errors.New("lists: malformed blob")

// ErrUnsupportedBlob is a blob of a format version this reader doesn't know.
var ErrUnsupportedBlob = errors.New("lists: unsupported blob version")

// Blob encodes s canonically.
func (s *Set) Blob() []byte {
	out := append([]byte(blobMagic), blobVersion)
	var spans [2][]span
	if s != nil {
		spans = s.spans
	}
	for f := range spans {
		n := 0
		for _, sp := range spans[f] {
			n += countPrefixes(family(f), sp)
		}
		out = binary.AppendUvarint(out, uint64(n))
		for _, sp := range spans[f] {
			eachPrefix(family(f), sp, func(first u128, bits int) {
				out = appendPrefix(out, family(f), first, bits)
			})
		}
	}
	return out
}

func appendPrefix(out []byte, f family, first u128, bits int) []byte {
	out = append(out, byte(bits))
	var full [16]byte
	binary.BigEndian.PutUint64(full[:8], first.hi)
	binary.BigEndian.PutUint64(full[8:], first.lo)
	addr := full[:]
	if f == fam4 {
		addr = full[12:]
	}
	return append(out, addr[:(bits+7)/8]...)
}

// Decode reads a blob made by [Set.Blob]. It accepts only the canonical
// encoding, so a set decoded from a blob encodes back to the same bytes and
// the same hash.
func Decode(blob []byte) (*Set, error) {
	rest, ok := bytes.CutPrefix(blob, []byte(blobMagic))
	if !ok || len(rest) == 0 {
		return nil, fmt.Errorf("%w: no header", ErrMalformedBlob)
	}
	if rest[0] != blobVersion {
		return nil, fmt.Errorf("%w %d", ErrUnsupportedBlob, rest[0])
	}
	rest = rest[1:]
	var b Builder
	for f := range b.spans {
		n, k := binary.Uvarint(rest)
		// Every prefix takes at least one byte, which bounds the allocation.
		if k <= 0 || n > uint64(len(rest)-k) {
			return nil, fmt.Errorf("%w: bad prefix count", ErrMalformedBlob)
		}
		rest = rest[k:]
		b.spans[f] = make([]span, 0, min(n, 1<<16))
		w := family(f).width()
		for range n {
			if len(rest) == 0 || int(rest[0]) > w {
				return nil, fmt.Errorf("%w: bad prefix length", ErrMalformedBlob)
			}
			bits := int(rest[0])
			size := (bits + 7) / 8
			if len(rest) < 1+size {
				return nil, fmt.Errorf("%w: truncated", ErrMalformedBlob)
			}
			var full [16]byte
			if family(f) == fam4 {
				copy(full[12:], rest[1:1+size])
			} else {
				copy(full[:], rest[1:1+size])
			}
			rest = rest[1+size:]
			v := u128{binary.BigEndian.Uint64(full[:8]), binary.BigEndian.Uint64(full[8:])}
			sp := span{v, v.or(lowMask(w - bits))}
			// Ascending and disjoint as we go, so memory grows only with
			// prefixes that could be part of a canonical set.
			if k := len(b.spans[f]); k > 0 && !b.spans[f][k-1].last.less(sp.first) {
				return nil, fmt.Errorf("%w: prefixes not ascending", ErrMalformedBlob)
			}
			b.spans[f] = append(b.spans[f], sp)
		}
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrMalformedBlob)
	}
	// Canonical means: re-encoding gives the same bytes. That rejects
	// unsorted, overlapping or mergeable prefixes, host bits and overlong
	// varints without a rule for each.
	s, _ := b.Build()
	if !bytes.Equal(s.Blob(), blob) {
		return nil, fmt.Errorf("%w: not canonical", ErrMalformedBlob)
	}
	return s, nil
}
