package censor

import (
	"slices"
	"sort"
)

// retainBytes bounds what the censor keeps of one direction of a flow:
// the stream prefix, and the out-of-order bytes waiting for a gap to
// fill. A ClientHello with a post-quantum key share is under 2 KB.
const retainBytes = 16 << 10

// windowBound is the farthest past the next in-order byte a segment may
// start and still be read: 32 MiB, several times the 6 MiB receive buffer
// Linux's long-standing default tcp_rmem allows at most, so it stays past
// any window a lab receiver advertises even if a newer kernel raises that
// default. A segment starting beyond it is one the receiver discards as
// outside its window.
const windowBound = 32 << 20

// Why a stream keeps a segment's payload out: the receiver (Linux, without
// TCP Fast Open) discards it too. Each is logged once per flow (EventIgnore).
const (
	ignoreBadChecksum = "bad checksum"
	ignoreSYNData     = "data on a SYN"
	ignoreRSTData     = "data on an RST"
	ignoreNoACK       = "data without ACK"
	ignoreWindow      = "beyond the receive window"
	// Not a discard by the receiver: the censor's own out-of-order buffer
	// was full and dropped its farthest bytes (Stream.Broken).
	ignoreEvicted = "out-of-order buffer full"
)

// Stream is one direction of a TCP connection as a Linux receiver reads
// it: the sender's bytes in order, rebuilt from segments that arrive out
// of order, overlap or repeat, keeping the bytes Linux keeps where copies
// differ, and leaving out what Linux discards (see doc.go "Limits" for
// what it still reads differently). It keeps the first retainBytes (the
// prefix: a ClientHello, a server's first flight) and, for every packet,
// the bytes that packet made readable in order (Fresh), so a module can
// follow the whole stream without the censor keeping it.
//
// The bytes are what the sender sent through the censor, including
// segments a verdict then dropped: their retransmissions are duplicates.
type Stream struct {
	// synced: nextSeq is known, from a SYN or, midstream, from the first
	// segment with data.
	synced, midstream bool
	isn               uint32 // the SYN's sequence number, unless midstream
	nextSeq           uint32 // sequence number of the next in-order byte
	delivered         uint64
	prefix            []byte
	pending           []segment // out of order, sorted by offset, no two alike
	pendingBytes      int
	broken            bool
	fresh             []byte
}

type segment struct {
	off  uint64 // stream offset of data[0]
	data []byte
}

func (g segment) end() uint64 { return g.off + uint64(len(g.data)) }

// Prefix is the stream's first bytes, up to retainBytes. It grows as
// segments arrive; a module that keeps it past Inspect clones it.
func (s *Stream) Prefix() []byte { return s.prefix }

// Fresh is what the flow's latest packet made readable in order: its own
// data past what was already delivered, and any buffered out-of-order
// bytes it joined. It is valid until the next packet of the flow.
func (s *Stream) Fresh() []byte { return s.fresh }

// Delivered counts the bytes readable in order so far, past the prefix
// too.
func (s *Stream) Delivered() uint64 { return s.delivered }

// Midstream reports a stream whose SYN the censor never saw: offset 0 is
// the first byte it saw, not the connection's first.
func (s *Stream) Midstream() bool { return s.midstream }

// Broken reports a stream whose out-of-order bytes outgrew retainBytes, so
// the farthest of them were dropped: Prefix and Fresh stay right up to the
// first dropped byte, and delivery stops there if the gap before it fills
// and its sender never sends it again.
func (s *Stream) Broken() bool { return s.broken }

// newConnection reports whether a SYN at seq opens a connection other than
// the one the stream is of.
func (s *Stream) newConnection(seq uint32) bool {
	return !s.synced || s.midstream || seq != s.isn
}

// add takes one segment of this direction, and returns why it kept the
// payload out, "" when it didn't (or there was none).
func (s *Stream) add(seq uint32, flags uint8, payload []byte) string {
	s.fresh = s.fresh[:0]
	if flags&Syn != 0 {
		if !s.synced {
			s.synced, s.isn, s.nextSeq = true, seq, seq+1
		}
		if len(payload) > 0 {
			// Linux reads a SYN's data only with TCP Fast Open, which a
			// lab server doesn't enable.
			return ignoreSYNData
		}
		return ""
	}
	switch {
	case len(payload) == 0:
		return ""
	case flags&Rst != 0:
		return ignoreRSTData
	case flags&Ack == 0:
		return ignoreNoACK
	}
	if !s.synced {
		s.synced, s.midstream, s.nextSeq = true, true, seq
	}
	// Sequence numbers wrap: compare by signed distance.
	rel := int64(int32(seq - s.nextSeq))
	if rel < 0 {
		if -rel >= int64(len(payload)) {
			return "" // a repeat of delivered bytes
		}
		payload, rel = payload[-rel:], 0
	}
	if rel >= windowBound {
		return ignoreWindow
	}
	if rel > 0 {
		return s.hold(s.delivered+uint64(rel), payload)
	}
	// In order: these bytes are read first, whatever waits out of order
	// for the same offsets.
	s.deliver(payload)
	for len(s.pending) > 0 && s.pending[0].off <= s.delivered {
		p := s.pending[0]
		s.pending = s.pending[1:]
		s.pendingBytes -= len(p.data)
		if p.end() > s.delivered {
			s.deliver(p.data[s.delivered-p.off:])
		}
	}
	return ""
}

func (s *Stream) deliver(b []byte) {
	if room := retainBytes - len(s.prefix); room > 0 {
		s.prefix = append(s.prefix, b[:min(room, len(b))]...)
	}
	s.fresh = append(s.fresh, b...)
	s.delivered += uint64(len(b))
	s.nextSeq += uint32(len(b))
}

// hold buffers an out-of-order segment until the gap before it fills, by
// Linux's rules for its out-of-order queue (tcp_data_queue_ofo), which
// decide whose bytes are read where copies overlap: segments are read in
// order of their first byte, so of two overlapping copies the one starting
// first wins; a segment whose bytes all wait already is dropped, so at one
// offset the first copy wins; one starting where another starts and
// reaching further replaces it; one starting where another ends is merged
// into it; and a segment drops the later ones it covers whole.
func (s *Stream) hold(off uint64, b []byte) string {
	end := off + uint64(len(b))
	i := sort.Search(len(s.pending), func(j int) bool { return s.pending[j].off > off })
	if i > 0 {
		p := &s.pending[i-1]
		switch {
		case end <= p.end():
			return ""
		case off == p.off:
			i--
			s.pendingBytes -= len(p.data)
			s.pending = slices.Delete(s.pending, i, i+1)
		case off == p.end():
			p.data = append(p.data, b...)
			s.pendingBytes += len(b)
			return s.evict()
		}
	}
	j := i
	for j < len(s.pending) && s.pending[j].end() <= end {
		s.pendingBytes -= len(s.pending[j].data)
		j++
	}
	s.pending = slices.Replace(s.pending, i, j, segment{off: off, data: append([]byte(nil), b...)})
	s.pendingBytes += len(b)
	return s.evict()
}

// evict drops the farthest out-of-order bytes past retainBytes: the bytes
// nearest the gap are the next to be read, so far junk never displaces
// them.
func (s *Stream) evict() string {
	if s.pendingBytes <= retainBytes {
		return ""
	}
	for s.pendingBytes > retainBytes {
		last := &s.pending[len(s.pending)-1]
		over := s.pendingBytes - retainBytes
		if over < len(last.data) {
			last.data = last.data[:len(last.data)-over]
			s.pendingBytes -= over
			break
		}
		s.pendingBytes -= len(last.data)
		s.pending = s.pending[:len(s.pending)-1]
	}
	s.broken = true
	return ignoreEvicted
}
