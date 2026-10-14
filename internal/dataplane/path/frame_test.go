package path

import (
	"bytes"
	"testing"
)

func TestWgDataLen(t *testing.T) {
	for _, tc := range []struct {
		n  int
		ok bool
	}{
		{32, true},   // keepalive, content 0
		{48, true},   // small padded data
		{1360, true}, // 32+1328, unshaped full MTU
		{1260, true}, // 32+1228, shaped full MTU from a remote sender
		{1308, true}, // 32+1276, shaped full MTU
		{608, true},  // 32+576, content at minOverlayMTU
		{612, true},  // content 580: capped padding, not a multiple of 16
		{50, false},  // junk below minOverlayMTU, not a multiple of 16
		{31, false},
	} {
		if got := wgDataLen(tc.n); got != tc.ok {
			t.Errorf("wgDataLen(%d) = %v, want %v", tc.n, got, tc.ok)
		}
	}
}

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
