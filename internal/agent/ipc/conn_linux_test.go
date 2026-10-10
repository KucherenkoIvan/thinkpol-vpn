//go:build linux

package ipc_test

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
)

func pair(t *testing.T) (*ipc.Conn, *ipc.Conn) {
	t.Helper()
	sup, f, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Close() })
	w, err := ipc.FromFile(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return sup, w
}

func TestMessagesKeepTheirBoundaries(t *testing.T) {
	sup, w := pair(t)
	init := ipc.Init{
		Space: "00112233445566778899aabbccddeeff", Interface: "veth0",
		Addrs:    []netip.Prefix{netip.MustParsePrefix("169.254.100.2/30")},
		Gateways: []netip.Addr{netip.MustParseAddr("169.254.100.1")},
		UID:      7, GID: 8,
	}
	m, err := ipc.InitMessage(init)
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte{0xa5}, ipc.MaxMessageSize-1)
	for _, msg := range []ipc.Message{m, {Kind: ipc.KindStop}, {Kind: 200, Payload: big}} {
		if err := sup.Send(msg); err != nil {
			t.Fatal(err)
		}
	}
	got, err := w.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := ipc.DecodeInit(got); err != nil || back.Space != init.Space || back.UID != 7 || back.Addrs[0] != init.Addrs[0] {
		t.Fatalf("init %+v, %v", back, err)
	}
	if got, err := w.Receive(); err != nil || got.Kind != ipc.KindStop || len(got.Payload) != 0 {
		t.Fatalf("stop: %+v, %v", got, err)
	}
	if got, err := w.Receive(); err != nil || got.Kind != 200 || !bytes.Equal(got.Payload, big) {
		t.Fatalf("largest message: kind %v, %d bytes, %v", got.Kind, len(got.Payload), err)
	}
}

func TestOversizedMessagesAreRefused(t *testing.T) {
	sup, _ := pair(t)
	if err := sup.Send(ipc.Message{Kind: ipc.KindStop, Payload: make([]byte, ipc.MaxMessageSize)}); err == nil {
		t.Fatal("oversized message sent")
	}
	files := make([]*os.File, ipc.MaxFiles+1)
	for i := range files {
		files[i] = os.Stdin
	}
	if err := sup.Send(ipc.Message{Kind: ipc.KindStop, Files: files}); err == nil {
		t.Fatal("too many files sent")
	}
}

// A descriptor passed over the socket is the same open file at the other
// end: what the stream handoff relies on.
func TestPassesFileDescriptors(t *testing.T) {
	sup, w := pair(t)
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := sup.Send(ipc.Message{Kind: 9, Payload: []byte("consumed"), Files: []*os.File{wr}}); err != nil {
		t.Fatal(err)
	}
	_ = wr.Close() // the sender's copy; the receiver's stays open
	got, err := w.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != "consumed" || len(got.Files) != 1 {
		t.Fatalf("got %q with %d files", got.Payload, len(got.Files))
	}
	if _, err := got.Files[0].Write([]byte("through")); err != nil {
		t.Fatal(err)
	}
	got.CloseFiles()
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "through" {
		t.Fatalf("read %q, %v", b, err)
	}
}

func TestClosedPeerIsEOF(t *testing.T) {
	sup, w := pair(t)
	_ = sup.Close()
	if _, err := w.Receive(); !errors.Is(err, io.EOF) {
		t.Fatalf("receive after the peer closed: %v, want EOF", err)
	}
}

func TestOnlySeqpacketSockets(t *testing.T) {
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = wr.Close() }()
	if _, err := ipc.FromFile(r); err == nil {
		t.Fatal("a pipe was taken for the socket")
	}
}
