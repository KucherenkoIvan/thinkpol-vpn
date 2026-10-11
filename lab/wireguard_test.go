package lab

import (
	"bytes"
	"testing"
)

// The signature's edges; TestCaptureFlagsRawWireGuard (a lab test) checks
// it against real WireGuard at the router.
func TestLooksLikeWireGuard(t *testing.T) {
	msg := func(typ byte, size int) []byte {
		return append([]byte{typ, 0, 0, 0}, bytes.Repeat([]byte{0xa5}, size-4)...)
	}
	for _, c := range []struct {
		name         string
		payload      []byte
		header, want bool
	}{
		{"initiation", msg(1, 148), true, true},
		{"response", msg(2, 92), true, true},
		{"cookie reply", msg(3, 64), true, true},
		{"keepalive", msg(4, 32), true, true},
		{"transport data", msg(4, 32+1280), true, true},
		{"initiation of another size", msg(1, 149), true, false},
		{"response of another size", msg(2, 148), true, false},
		{"transport data off the 16-byte grid", msg(4, 33), true, false},
		{"transport data too short", msg(4, 16), true, false},
		{"type 0", msg(0, 148), false, false},
		{"type 5", msg(5, 148), false, false},
		{"reserved byte set", append([]byte{1, 0, 1, 0}, make([]byte, 144)...), false, false},
		{"too short for a header", []byte{1, 0, 0}, false, false},
	} {
		if got := LooksLikeWireGuard(c.payload); got != c.want {
			t.Errorf("%s: LooksLikeWireGuard = %v, want %v", c.name, got, c.want)
		}
		if got := WireGuardHeader(c.payload); got != c.header {
			t.Errorf("%s: WireGuardHeader = %v, want %v", c.name, got, c.header)
		}
	}
}

func TestWireGuardOffset(t *testing.T) {
	initiation := append([]byte{1, 0, 0, 0}, bytes.Repeat([]byte{0xa5}, 144)...)
	wrapped := append(bytes.Repeat([]byte{0x5a}, 18), initiation...)
	if got := WireGuardOffset(wrapped); got != 18 {
		t.Errorf("an initiation behind 18 bytes found at %d", got)
	}
	if got := WireGuardOffset(initiation); got != 0 {
		t.Errorf("a bare initiation found at %d", got)
	}
	if got := WireGuardOffset(append(wrapped, 0x5a)); got != -1 {
		t.Errorf("an initiation followed by a byte (not to the end) found at %d", got)
	}
	if got := WireGuardOffset(bytes.Repeat([]byte{0x5a}, 1400)); got != -1 {
		t.Errorf("found WireGuard at %d in filler", got)
	}
}
