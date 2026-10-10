package netmap

import (
	"bytes"
	"errors"
	"testing"
)

func TestSectionCount(t *testing.T) {
	tests := []struct{ real, want int }{
		{0, 8}, {1, 8}, {7, 8}, {8, 8}, {9, 16}, {16, 16}, {17, 32}, {31, 32}, {32, 32}, {33, 64}, {1024, 1024}, {1025, 2048},
	}
	for _, tt := range tests {
		if got := sectionCount(tt.real); got != tt.want {
			t.Errorf("sectionCount(%d) = %d, want %d", tt.real, got, tt.want)
		}
	}
}

func TestSectionSize(t *testing.T) {
	tests := []struct{ largest, want int }{
		{0, 8192}, {1, 8192}, {8191, 8192}, {8192, 16384}, {16383, 16384}, {16384, 32768}, {100_000, 131072},
	}
	for _, tt := range tests {
		if got := sectionSize(tt.largest); got != tt.want {
			t.Errorf("sectionSize(%d) = %d, want %d", tt.largest, got, tt.want)
		}
	}
}

func TestPadUnpad(t *testing.T) {
	for _, content := range [][]byte{nil, {0}, {0x80}, {1, 0, 0}, bytes.Repeat([]byte{0x80}, minSectionSize-1)} {
		padded := pad(content, minSectionSize)
		if len(padded) != minSectionSize {
			t.Fatalf("pad(%d bytes) = %d bytes", len(content), len(padded))
		}
		got, err := unpad(padded)
		if err != nil || !bytes.Equal(got, content) {
			t.Errorf("unpad(pad(%x)) = %x, %v", content, got, err)
		}
	}
	bad := map[string][]byte{
		"empty":          nil,
		"all zeros":      make([]byte, 16),
		"no marker":      {1, 2, 3, 0, 0},
		"wrong marker":   {1, 2, 0x81, 0},
		"marker missing": {1, 2, 3},
	}
	for name, b := range bad {
		if _, err := unpad(b); !errors.Is(err, errBadPadding) {
			t.Errorf("%s: err = %v, want errBadPadding", name, err)
		}
	}
}
