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

// pair makes a control socket pair and returns the supervisor and worker
// ends of it.
func pair(t *testing.T) (*ipc.Conn, *ipc.Conn) {
	t.Helper()
	ends, child, err := ipc.NewPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ends.Control.Close(); _ = ends.Data.Close() })
	w, err := ipc.FromFile(child[0])
	for _, f := range child {
		_ = f.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return ends.Control, w
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

func TestInitCarriesTheProtocolVersion(t *testing.T) {
	sup, w := pair(t)
	if err := sup.Send(ipc.Message{Kind: ipc.KindInit, Payload: []byte(`{"version":999,"space":"x"}`)}); err != nil {
		t.Fatal(err)
	}
	got, err := w.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.DecodeInit(got); err == nil {
		t.Fatal("a mismatched protocol version was accepted")
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
	if err := sup.Send(ipc.Message{Kind: ipc.KindStream, Payload: []byte("consumed"), Files: []*os.File{wr}}); err != nil {
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

// TrySend never blocks: when the worker stops reading the data socket, it
// fills, and further sends drop instead of blocking, counted in Drops.
func TestTrySendDropsWhenFull(t *testing.T) {
	ends, child, err := ipc.NewPair()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ends.Control.Close(); _ = ends.Data.Close() }()
	// Keep the worker's data end open but never read it.
	w, err := ipc.FromFile(child[1])
	for _, f := range child {
		_ = f.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()

	full := false
	for range 100000 {
		err := ends.Data.TrySend(ipc.Message{Kind: ipc.KindDatagram, Payload: bytes.Repeat([]byte{1}, 1024)})
		if errors.Is(err, ipc.ErrFull) {
			full = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !full {
		t.Fatal("TrySend never reported the buffer full")
	}
	if ends.Data.Drops() == 0 {
		t.Fatal("a full-buffer drop was not counted")
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
