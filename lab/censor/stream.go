package censor

import "slices"

// retainBytes bounds what the censor keeps of one direction of a flow:
// the stream prefix, and the out-of-order bytes waiting for a gap to
// fill. A ClientHello with a post-quantum key share is under 2 KB.
const retainBytes = 16 << 10

// Stream is one direction of a TCP connection as the receiving
// application would read it: the sender's bytes in order, rebuilt from
// segments that arrive out of order, overlap or repeat. It keeps the
// first retainBytes (the prefix: a ClientHello, a server's first flight)
// and, for every packet, the bytes that packet made readable in order
// (Fresh), so a module can follow the whole stream without the censor
// keeping it.
//
// The bytes are what the sender sent through the censor, including
// segments a verdict then dropped: their retransmissions are duplicates.
type Stream struct {
	// synced: nextSeq is known, from a SYN or, midstream, from the first
	// segment with data.
	synced, midstream bool
	nextSeq           uint32 // sequence number of the next in-order byte
	delivered         uint64
	prefix            []byte
	pending           []segment // out of order, sorted by offset
	pendingBytes      int
	broken            bool
	fresh             []byte
}

type segment struct {
	off  uint64 // stream offset of data[0]
	data []byte
}

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

// Broken reports a stream whose out-of-order bytes outgrew retainBytes:
// it delivers nothing more, and Prefix keeps what came before the gap.
func (s *Stream) Broken() bool { return s.broken }

// add takes one segment of this direction.
func (s *Stream) add(seq uint32, flags uint8, payload []byte) {
	s.fresh = s.fresh[:0]
	if flags&Syn != 0 {
		if !s.synced {
			s.synced, s.nextSeq = true, seq+1
		}
		seq++ // a SYN's data (TCP Fast Open) starts past it
	}
	if len(payload) == 0 || s.broken {
		return
	}
	if !s.synced {
		s.synced, s.midstream, s.nextSeq = true, true, seq
	}
	// Sequence numbers wrap: compare by signed distance.
	rel := int64(int32(seq - s.nextSeq))
	if rel < 0 {
		if -rel >= int64(len(payload)) {
			return // a repeat of delivered bytes
		}
		payload, rel = payload[-rel:], 0
	}
	if rel > 0 {
		s.hold(s.delivered+uint64(rel), payload)
		return
	}
	s.deliver(payload)
	for len(s.pending) > 0 && s.pending[0].off <= s.delivered {
		p := s.pending[0]
		s.pending = s.pending[1:]
		s.pendingBytes -= len(p.data)
		if end := p.off + uint64(len(p.data)); end > s.delivered {
			s.deliver(p.data[s.delivered-p.off:])
		}
	}
}

func (s *Stream) deliver(b []byte) {
	if room := retainBytes - len(s.prefix); room > 0 {
		s.prefix = append(s.prefix, b[:min(room, len(b))]...)
	}
	s.fresh = append(s.fresh, b...)
	s.delivered += uint64(len(b))
	s.nextSeq += uint32(len(b))
}

// hold buffers an out-of-order segment until the gap before it fills.
func (s *Stream) hold(off uint64, b []byte) {
	if s.pendingBytes+len(b) > retainBytes {
		s.broken, s.pending, s.pendingBytes = true, nil, 0
		return
	}
	i, _ := slices.BinarySearchFunc(s.pending, off, func(p segment, off uint64) int {
		switch {
		case p.off < off:
			return -1
		case p.off > off:
			return 1
		}
		return 0
	})
	s.pending = slices.Insert(s.pending, i, segment{off: off, data: append([]byte(nil), b...)})
	s.pendingBytes += len(b)
}
