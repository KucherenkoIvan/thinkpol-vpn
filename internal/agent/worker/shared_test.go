package worker

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
)

type sentDatagram struct {
	h ipc.DatagramHeader
	d string
}

type recordingSender struct {
	mu   sync.Mutex
	sent []sentDatagram
}

func (r *recordingSender) SendDatagram(h ipc.DatagramHeader, d []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, sentDatagram{h, string(d)})
	return nil
}

func datagram(listener uint32, from string, d string) []byte {
	b := make([]byte, ipc.DatagramHeaderSize, ipc.DatagramHeaderSize+len(d))
	ipc.DatagramHeader{Listener: listener, Remote: netip.MustParseAddrPort(from)}.Put(b)
	return append(b, d...)
}

func TestForwardedDatagramsReachTheirListener(t *testing.T) {
	send := &recordingSender{}
	s := newSharedListeners(send)
	ls := s.update([]ipc.Listener{{ID: 1, Transport: "udp", Address: "192.0.2.1:443"}, {ID: 2, Transport: "udp", Address: "[2001:db8::1]:443"}})
	if len(ls) != 2 || ls[0].Packets == nil || ls[1].Packets == nil || ls[0].Streams != nil {
		t.Fatalf("listeners %+v", ls)
	}
	if got := ls[0].Packets.LocalAddr().String(); got != "192.0.2.1:443" {
		t.Errorf("local address %s", got)
	}
	for _, d := range [][]byte{datagram(2, "[2001:db8::9]:5000", "to two"), datagram(1, "198.51.100.7:4000", "to one"), datagram(9, "198.51.100.7:4000", "to nobody")} {
		if err := s.datagram(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.datagram([]byte{1, 2}); err == nil {
		t.Fatal("a malformed datagram message was taken")
	}
	buf := make([]byte, 64)
	n, from, err := ls[0].Packets.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "to one" || from.String() != "198.51.100.7:4000" {
		t.Fatalf("listener 1 read %q from %v, %v", buf[:n], from, err)
	}
	n, from, err = ls[1].Packets.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "to two" || from.String() != "[2001:db8::9]:5000" {
		t.Fatalf("listener 2 read %q from %v, %v", buf[:n], from, err)
	}
	if _, err := ls[0].Packets.WriteTo([]byte("reply"), from); err != nil {
		t.Fatal(err)
	}
	want := sentDatagram{ipc.DatagramHeader{Listener: 1, Remote: netip.MustParseAddrPort("[2001:db8::9]:5000")}, "reply"}
	if len(send.sent) != 1 || send.sent[0] != want {
		t.Fatalf("sent %+v, want %+v", send.sent, want)
	}

	// Listener 1 stays the same; listener 2 goes.
	again := s.update([]ipc.Listener{{ID: 1, Transport: "udp", Address: "192.0.2.1:443"}})
	if len(again) != 1 || again[0].Packets != ls[0].Packets {
		t.Fatalf("a listener that stayed changed: %+v", again)
	}
	select {
	case <-ls[1].Done:
	default:
		t.Fatal("a listener that went isn't done")
	}
	if _, _, err := ls[1].Packets.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("reading a listener that went: %v", err)
	}
	if err := ls[0].Packets.SetReadDeadline(time.Now()); err == nil {
		t.Fatal("a deadline was taken and would be ignored")
	}
	_ = ls[0].Packets.Close()
	if _, err := ls[0].Packets.WriteTo([]byte("x"), from); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("writing a closed conn: %v", err)
	}
}

func TestAFullQueueDrops(t *testing.T) {
	s := newSharedListeners(&recordingSender{})
	ls := s.update([]ipc.Listener{{ID: 1, Transport: "udp", Address: "192.0.2.1:443"}})
	for range forwardedQueue + 10 {
		if err := s.datagram(datagram(1, "198.51.100.7:4000", "x")); err != nil {
			t.Fatal(err)
		}
	}
	if got := ls[0].Packets.(*forwardedConn).dropped.Load(); got != 10 {
		t.Fatalf("%d dropped, want 10", got)
	}
}

func TestHandedStreams(t *testing.T) {
	s := newSharedListeners(&recordingSender{})
	ls := s.update([]ipc.Listener{{ID: 3, Transport: "tls", Stream: true, Address: "192.0.2.1:443"}, {ID: 4, Transport: "udp", Address: "192.0.2.1:443"}})
	mine, theirs := net.Pipe()
	defer func() { _ = theirs.Close() }()
	s.stream(3, mine, []byte("hello"))
	select {
	case st := <-ls[0].Streams:
		if st.Conn != mine || string(st.Consumed) != "hello" {
			t.Fatalf("got %+v", st)
		}
	default:
		t.Fatal("no stream")
	}
	// To a datagram listener or an unknown one: closed.
	for _, id := range []uint32{4, 99} {
		a, b := net.Pipe()
		s.stream(id, a, nil)
		_ = b.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := b.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("listener %d: the connection stayed open (%v)", id, err)
		}
		_ = b.Close()
	}
}
