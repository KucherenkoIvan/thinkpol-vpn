package censor

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
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
// it, and keeps the nearest retainBytes out of order, dropping the
// farthest, rather than buffer more or stop.
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
	var why string
	for i := 1; i <= retainBytes/1000+1; i++ {
		why = s.add(seq+uint32(i)*1000, Ack, seg) // the segment at seq comes last
	}
	if !s.Broken() || s.pendingBytes != retainBytes || why != ignoreEvicted {
		t.Errorf("%d bytes waiting out of order: broken %v, %q", s.pendingBytes, s.Broken(), why)
	}
	s.add(seq, Ack, seg)
	if want := 1000 + retainBytes; len(s.Fresh()) != want || s.Delivered() != uint64(20000+want) {
		t.Errorf("the gap filled: fresh %d, delivered %d, want the nearest %d bytes", len(s.Fresh()), s.Delivered(), want)
	}
}

// TestStreamFarSegments: a segment past the receive window is kept out, as
// the receiver discards it, and far junk inside the window, more than the
// out-of-order buffer holds, never keeps the stream from reading what
// comes in order: the ClientHello after either is the prefix.
func TestStreamFarSegments(t *testing.T) {
	ch := clientHello(t)
	junk := bytes.Repeat([]byte{0xee}, 1400)
	for _, c := range []struct {
		name     string
		ahead    uint32
		wantWhy  string
		wantGone bool
	}{
		{"past the window", 1 << 30, ignoreWindow, false},
		{"inside the window", 1 << 20, ignoreEvicted, true},
	} {
		var s Stream
		s.add(1000, Syn, nil)
		var why string
		for i := uint32(0); i < 13; i++ { // 18200 bytes
			if w := s.add(1001+c.ahead+i*1400, Ack, junk); w != "" {
				why = w
			}
		}
		if why != c.wantWhy || s.Broken() != c.wantGone {
			t.Errorf("%s: junk kept out as %q, broken %v; want %q, broken %v", c.name, why, s.Broken(), c.wantWhy, c.wantGone)
		}
		s.add(1001, Ack|Psh, ch)
		if !bytes.Equal(s.Prefix(), ch) {
			t.Errorf("%s: after the junk the prefix is %d bytes, want the %d-byte ClientHello", c.name, len(s.Prefix()), len(ch))
		}
	}
}

// TestStreamOverlapKeepsLinuxBytes: where out-of-order copies of the same
// bytes differ, the stream reads the copy Linux reads.
func TestStreamOverlapKeepsLinuxBytes(t *testing.T) {
	for _, c := range []struct {
		name string
		segs []string // "offset:bytes", offsets past the gap at 0
		want string
	}{
		// Same offset and length: the first copy stays.
		{"same offset", []string{"4:real", "4:fake"}, "abcdreal"},
		// Same offset, the later one longer: it replaces the first.
		{"same offset, longer", []string{"4:re", "4:real"}, "abcdreal"},
		// Starting inside an earlier one: the earlier one's bytes.
		{"partial overlap", []string{"4:real", "6:KEtail"}, "abcdrealtail"},
		// Two adjacent copies are merged, so a third at the joint
		// overlaps the merged one partly: its bytes there lose.
		{"merged neighbours", []string{"4:re", "6:al", "6:XXtail"}, "abcdrealtail"},
		// A later copy covering earlier ones whole drops them.
		{"covering", []string{"6:xx", "4:real"}, "abcdreal"},
	} {
		var s Stream
		s.add(0, Syn, nil)
		for _, g := range c.segs {
			off, data, _ := strings.Cut(g, ":")
			n, _ := strconv.Atoi(off)
			s.add(1+uint32(n), Ack, []byte(data))
		}
		s.add(1, Ack, []byte("abcd"))
		if string(s.Prefix()) != c.want {
			t.Errorf("%s: read %q, want %q", c.name, s.Prefix(), c.want)
		}
	}
}

// TestStreamKeepsOutWhatReceiverDiscards: data on a SYN (no TCP Fast Open
// in the lab), data without ACK and data on an RST never enter the stream,
// so the real bytes sent after such a decoy at the same sequence number
// are what the stream reads.
func TestStreamKeepsOutWhatReceiverDiscards(t *testing.T) {
	for _, c := range []struct {
		flags uint8
		seq   uint32
		why   string
	}{
		{Syn, 1000, ignoreSYNData},
		{Psh, 1001, ignoreNoACK},
		{Rst | Ack, 1001, ignoreRSTData},
	} {
		var s Stream
		if c.flags&Syn == 0 {
			s.add(1000, Syn, nil)
		}
		if why := s.add(c.seq, c.flags, []byte("decoy")); why != c.why {
			t.Errorf("flags %#x: kept out as %q, want %q", c.flags, why, c.why)
		}
		s.add(1001, Ack|Psh, []byte("real!"))
		if string(s.Prefix()) != "real!" {
			t.Errorf("flags %#x: read %q, want the real bytes", c.flags, s.Prefix())
		}
	}
}
