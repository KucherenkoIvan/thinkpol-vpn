package censor

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// clientHello is the first TLS record a Go client sends: a real
// ClientHello, with the post-quantum key share Go offers by default.
func clientHello(t *testing.T) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: "example.net"}).Handshake()
		_ = c.Close()
	}()
	defer func() { _ = s.Close() }()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(s, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestStreamInOrder(t *testing.T) {
	ch := clientHello(t)
	var s Stream
	s.add(1000, Syn, nil)
	s.add(1001, Ack|Psh, ch[:100])
	if !bytes.Equal(s.Prefix(), ch[:100]) || !bytes.Equal(s.Fresh(), ch[:100]) {
		t.Fatalf("after the first segment: prefix %d bytes, fresh %d", len(s.Prefix()), len(s.Fresh()))
	}
	s.add(1101, Ack|Psh, ch[100:])
	if !bytes.Equal(s.Prefix(), ch) || !bytes.Equal(s.Fresh(), ch[100:]) || s.Delivered() != uint64(len(ch)) {
		t.Errorf("after the second: prefix %d bytes, fresh %d, delivered %d", len(s.Prefix()), len(s.Fresh()), s.Delivered())
	}
	if s.Midstream() || s.Broken() {
		t.Error("a whole stream reads as midstream or broken")
	}
}

// TestStreamOutOfOrder: a segment ahead of a gap waits, and the one that
// fills the gap makes both readable.
func TestStreamOutOfOrder(t *testing.T) {
	ch := clientHello(t)
	var s Stream
	s.add(1000, Syn, nil)
	s.add(1101, Ack|Psh, ch[100:])
	if len(s.Prefix()) != 0 || len(s.Fresh()) != 0 {
		t.Fatalf("bytes past a gap are readable: prefix %d, fresh %d", len(s.Prefix()), len(s.Fresh()))
	}
	s.add(1001, Ack|Psh, ch[:100])
	if !bytes.Equal(s.Prefix(), ch) || !bytes.Equal(s.Fresh(), ch) {
		t.Errorf("after the gap filled: prefix %d bytes, fresh %d", len(s.Prefix()), len(s.Fresh()))
	}
}

// TestStreamRepeats: retransmitted and overlapping segments add only
// their new bytes.
func TestStreamRepeats(t *testing.T) {
	var s Stream
	s.add(0, Syn, nil)
	s.add(1, Ack, []byte("abcd"))
	s.add(1, Ack, []byte("abcd"))
	if len(s.Fresh()) != 0 {
		t.Errorf("a retransmission was fresh: %q", s.Fresh())
	}
	s.add(3, Ack, []byte("cdef"))
	if string(s.Fresh()) != "ef" || string(s.Prefix()) != "abcdef" {
		t.Errorf("overlap: fresh %q, prefix %q", s.Fresh(), s.Prefix())
	}
	// Out of order and overlapping each other.
	s.add(10, Ack, []byte("jkl"))
	s.add(9, Ack, []byte("ijk"))
	s.add(7, Ack, []byte("gh"))
	if string(s.Fresh()) != "ghijkl" || string(s.Prefix()) != "abcdefghijkl" {
		t.Errorf("pending overlap: fresh %q, prefix %q", s.Fresh(), s.Prefix())
	}
}

// TestStreamWraps reassembles across the sequence number wrap.
func TestStreamWraps(t *testing.T) {
	var s Stream
	s.add(0xfffffffd, Syn, nil)
	s.add(0x00000001, Ack, []byte("cd")) // ahead, past the wrap
	s.add(0xfffffffe, Ack, []byte("ab")) // 0xfffffffe, 0xffffffff
	s.add(0x00000000, Ack, []byte("x"))  // fills the gap
	if string(s.Prefix()) != "abxcd" {
		t.Errorf("prefix %q across the wrap", s.Prefix())
	}
}

// TestStreamMidstream starts at the first data the censor sees.
func TestStreamMidstream(t *testing.T) {
	var s Stream
	s.add(5000, Ack, []byte("late"))
	s.add(4990, Ack, []byte("0123456789"))
	if !s.Midstream() || string(s.Prefix()) != "late" {
		t.Errorf("midstream %v, prefix %q", s.Midstream(), s.Prefix())
	}
}

// TestStreamBounds keeps retainBytes of prefix while still delivering past
// it, and breaks rather than buffer more than retainBytes out of order.
func TestStreamBounds(t *testing.T) {
	var s Stream
	s.add(0, Syn, nil)
	seg := bytes.Repeat([]byte{7}, 1000)
	seq := uint32(1)
	for i := 0; i < 20; i++ {
		s.add(seq, Ack, seg)
		seq += 1000
	}
	if len(s.Prefix()) != retainBytes || s.Delivered() != 20000 || len(s.Fresh()) != 1000 {
		t.Errorf("prefix %d, delivered %d, fresh %d", len(s.Prefix()), s.Delivered(), len(s.Fresh()))
	}
	for i := 1; i <= retainBytes/1000+1; i++ {
		s.add(seq+uint32(i)*1000, Ack, seg) // the segment at seq never comes
	}
	if !s.Broken() || len(s.pending) != 0 {
		t.Errorf("%d bytes waiting out of order: broken %v", s.pendingBytes, s.Broken())
	}
	s.add(seq, Ack, seg)
	if len(s.Fresh()) != 0 || s.Delivered() != 20000 {
		t.Errorf("a broken stream delivered: fresh %d, delivered %d", len(s.Fresh()), s.Delivered())
	}
}
