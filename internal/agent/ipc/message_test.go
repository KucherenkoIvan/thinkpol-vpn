package ipc_test

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
)

func TestInitRoundTrip(t *testing.T) {
	in := ipc.Init{
		Space:     "00112233445566778899aabbccddeeff",
		Interface: "veth0",
		Addrs:     []netip.Prefix{netip.MustParsePrefix("169.254.100.2/30"), netip.MustParsePrefix("fd74:7470::2/64")},
		Gateways:  []netip.Addr{netip.MustParseAddr("169.254.100.1"), netip.MustParseAddr("fd74:7470::1")},
		Version:   1, UID: 1000, GID: 1001,
	}
	m, err := ipc.InitMessage(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ipc.DecodeInit(m)
	if err != nil {
		t.Fatal(err)
	}
	if out.Space != in.Space || out.Interface != in.Interface || out.UID != in.UID || out.GID != in.GID ||
		len(out.Addrs) != 2 || out.Addrs[1] != in.Addrs[1] || out.Gateways[0] != in.Gateways[0] {
		t.Fatalf("round trip: %+v, want %+v", out, in)
	}
	if _, err := ipc.DecodeInit(ipc.Message{Kind: ipc.KindReady}); err == nil {
		t.Fatal("decoded a ready message as init")
	}
}

func TestDatagramHeaderRoundTrip(t *testing.T) {
	for _, remote := range []string{"192.0.2.7:51820", "[2001:db8::1]:443", "[::ffff:192.0.2.7]:9", "0.0.0.0:0"} {
		h := ipc.DatagramHeader{Listener: 0xdeadbeef, Remote: netip.MustParseAddrPort(remote)}
		b := make([]byte, ipc.DatagramHeaderSize, ipc.DatagramHeaderSize+3)
		h.Put(b)
		b = append(b, 1, 2, 3)
		got, d, err := ipc.ParseDatagram(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != h || string(d) != "\x01\x02\x03" {
			t.Errorf("%s: round trip gave %+v %v", remote, got, d)
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, ipc.DatagramHeaderSize-1), make([]byte, ipc.DatagramHeaderSize)} {
		if _, _, err := ipc.ParseDatagram(bad); err == nil {
			t.Errorf("parsed a malformed header %x", bad)
		}
	}
}

func TestListenersRoundTrip(t *testing.T) {
	in := []ipc.Listener{{ID: 1, Transport: "udp", Address: "0.0.0.0:443"}, {ID: 7, Transport: "reality", Stream: true, Address: "[::]:443", Handoff: []byte{0, 1, 2}}}
	m, err := ipc.ListenersMessage(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ipc.DecodeListeners(m)
	if err != nil || !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip: %+v, %v", out, err)
	}
	m, _ = ipc.ListenersMessage(nil)
	if out, err := ipc.DecodeListeners(m); err != nil || out == nil || len(out) != 0 {
		t.Fatalf("no listeners: %+v, %v", out, err)
	}
}

// A Stream message keeps the consumed bytes and the target's apart, with
// or without a target descriptor, and refuses a payload whose lengths
// don't add up.
func TestStreamRoundTrip(t *testing.T) {
	files := func(n int) []*os.File {
		var fs []*os.File
		for range n {
			f, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			fs = append(fs, f)
		}
		return fs
	}
	fs := files(2)
	in := ipc.Stream{Listener: 9, Consumed: []byte("hello"), TargetRead: []byte("early")}
	s, conn, target, err := ipc.DecodeStream(ipc.StreamMessage(in, fs[0], fs[1]))
	if err != nil || !reflect.DeepEqual(s, in) || conn != fs[0] || target != fs[1] {
		t.Fatalf("with a target: %+v %v %v, %v", s, conn, target, err)
	}
	in = ipc.Stream{Listener: 3, Consumed: []byte("line\n"), TargetRead: []byte{}}
	s, conn, target, err = ipc.DecodeStream(ipc.StreamMessage(in, fs[0], nil))
	if err != nil || !reflect.DeepEqual(s, in) || conn != fs[0] || target != nil {
		t.Fatalf("without a target: %+v %v %v, %v", s, conn, target, err)
	}
	for name, m := range map[string]ipc.Message{
		"consumed past the payload": {Kind: ipc.KindStream, Payload: []byte{0, 0, 0, 1, 0, 0, 0, 9, 'x'}, Files: files(2)},
		"target bytes, no target":   {Kind: ipc.KindStream, Payload: []byte{0, 0, 0, 1, 0, 0, 0, 0, 'x'}, Files: files(1)},
		"no descriptor":             {Kind: ipc.KindStream, Payload: []byte{0, 0, 0, 1, 0, 0, 0, 0}},
		"three descriptors":         {Kind: ipc.KindStream, Payload: []byte{0, 0, 0, 1, 0, 0, 0, 0}, Files: files(3)},
	} {
		if _, _, _, err := ipc.DecodeStream(m); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func TestCountersRoundTrip(t *testing.T) {
	in := ipc.SharedCounters{Forwarded: 1, ForwardedBytes: 2, Replayed: 3, RepliesNotAllowed: 4, ReplyPeersEvicted: 5}
	m, err := ipc.CountersMessage(in)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := ipc.DecodeCounters(m); err != nil || out != in {
		t.Fatalf("round trip: %+v, %v", out, err)
	}
	if _, err := ipc.DecodeCounters(ipc.Message{Kind: ipc.KindListeners}); err == nil {
		t.Fatal("decoded listeners as counters")
	}
}
