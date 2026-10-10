package path

import (
	"bytes"
	"testing"
)

func TestPacketHeader(t *testing.T) {
	h := header{hopLimit: 3, dst: NodeID{1, 2, 3, 4, 5, 6, 7, 8}, src: NodeID{9, 10, 11, 12, 13, 14, 15, 16}}
	msg := []byte("a WireGuard message")
	f := make([]byte, HeaderSize+len(msg))
	putHeader(f, h)
	copy(f[HeaderSize:], msg)
	want := append([]byte{kindPacket, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, msg...)
	if !bytes.Equal(f, want) {
		t.Fatalf("frame %x, want %x", f, want)
	}
	got, ok := parsePacket(f)
	if !ok || got != h {
		t.Fatalf("parsed %+v (%v), want %+v", got, ok, h)
	}

	for name, bad := range map[string][]byte{
		"empty":           {},
		"header only":     f[:HeaderSize],
		"short header":    f[:HeaderSize-1],
		"no hops left":    append([]byte{kindPacket, 0}, f[2:]...),
		"a probe":         append([]byte{kindProbe}, f[1:]...),
		"an unknown kind": append([]byte{0xff}, f[1:]...),
	} {
		if _, ok := parsePacket(bad); ok {
			t.Errorf("%s: parsed as a packet", name)
		}
	}
}
