package netmap

import (
	"errors"
	"math/bits"
)

// Padding hides the number of nodes (S6) and what each node does: the section
// count is a power of two, at least minSections, and every section of an
// envelope has the same padded length, a power of two of at least
// minSectionSize bytes.
const (
	minSections    = 8
	maxSections    = 1024
	minSectionSize = 1 << 10
	maxSectionSize = 1 << 20
)

// sectionCount is the padded section count for n real sections.
func sectionCount(n int) int {
	if n <= minSections {
		return minSections
	}
	return 1 << bits.Len(uint(n-1))
}

// sectionSize is the padded plaintext length for a largest serialized
// section of n bytes: room for the content and the 0x80 marker.
func sectionSize(n int) int {
	size := minSectionSize
	for size < n+1 {
		size <<= 1
	}
	return size
}

func isPowerOfTwo(n int) bool { return n > 0 && n&(n-1) == 0 }

// pad appends ISO/IEC 7816-4 padding to b: 0x80, then zeros up to size.
func pad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

var errBadPadding = errors.New("bad padding")

// unpad strips the padding pad added. It runs only on authenticated
// plaintext, so its timing reveals nothing to an attacker.
func unpad(b []byte) ([]byte, error) {
	i := len(b) - 1
	for i >= 0 && b[i] == 0 {
		i--
	}
	if i < 0 || b[i] != 0x80 {
		return nil, errBadPadding
	}
	return b[:i], nil
}
