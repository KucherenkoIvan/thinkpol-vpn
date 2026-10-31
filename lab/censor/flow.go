package censor

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FlowKey is one directional flow: everything from one socket to another.
// The replies are a flow of their own.
type FlowKey struct {
	Proto            Proto
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
}

// Reverse is the key of the replies.
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{Proto: k.Proto, Src: k.Dst, Dst: k.Src, SrcPort: k.DstPort, DstPort: k.SrcPort}
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s %s:%d->%s:%d", k.Proto, k.Src, k.SrcPort, k.Dst, k.DstPort)
}

// ParseFlowKey reads what FlowKey.String wrote.
func ParseFlowKey(s string) (FlowKey, error) {
	proto, rest, ok := strings.Cut(s, " ")
	if !ok {
		return FlowKey{}, fmt.Errorf("flow %q", s)
	}
	left, right, ok := strings.Cut(rest, "->")
	if !ok {
		return FlowKey{}, fmt.Errorf("flow %q", s)
	}
	src, srcPort, err := parseHostPort(left)
	if err != nil {
		return FlowKey{}, fmt.Errorf("flow %q: %w", s, err)
	}
	dst, dstPort, err := parseHostPort(right)
	if err != nil {
		return FlowKey{}, fmt.Errorf("flow %q: %w", s, err)
	}
	var p Proto
	switch proto {
	case "tcp":
		p = ProtoTCP
	case "udp":
		p = ProtoUDP
	default:
		return FlowKey{}, fmt.Errorf("flow %q: protocol %q", s, proto)
	}
	return FlowKey{Proto: p, Src: src, Dst: dst, SrcPort: srcPort, DstPort: dstPort}, nil
}

func parseHostPort(s string) (netip.Addr, uint16, error) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ':' {
			continue
		}
		port, err := strconv.ParseUint(s[i+1:], 10, 16)
		if err != nil {
			continue
		}
		a, err := netip.ParseAddr(s[:i])
		if err != nil {
			continue
		}
		return a, uint16(port), nil
	}
	return netip.Addr{}, 0, fmt.Errorf("host:port %q", s)
}

// Flow is the censor's state of one direction of a flow, given to the
// passive modules with every packet of it. It is only ever touched from
// the queue's serial callback, so a module reads it without locking; per-
// flow state of a module's own is the module's business, keyed by FlowKey.
type Flow struct {
	Key     FlowKey
	Started time.Time
	// Last is when the censor saw the flow's latest packet.
	Last time.Time
	// Packets and Bytes (payload bytes) count what the censor saw in this
	// direction, the triggering packet included.
	Packets uint64
	Bytes   uint64
	// Stream is a TCP flow's bytes in order; nil for UDP.
	Stream *Stream
	// FirstDatagram is a UDP flow's first datagram with payload, up to
	// retainBytes; nil for TCP.
	FirstDatagram []byte

	reverse *Flow
	// pinned is the flow's terminal verdict, nil while none is.
	pinned *rule
	// done marks the passive modules (by index) that pinned a verdict:
	// they see the flow no more, the others still do.
	done []bool
	// tagged holds the modules that tagged the flow already.
	tagged map[string]bool
	bucket *tokenBucket
	// throttle is the first Throttle applied to the flow, which its
	// reverse is then pinned to as well.
	throttle *rule
	// logged holds every verdict and module the flow's decision entries
	// named, last the latest; applied counts its packets by what the
	// queue did.
	logged  map[ruleKey]bool
	last    ruleKey
	applied map[Verdict]uint64
	// ignored counts the packets whose payload the flow kept out, by why.
	ignored map[string]uint64
	// offer is the sequence number of a SYN that may open a new connection
	// on the flow's addresses and ports, offered while the reply to it
	// hasn't come.
	offer   uint32
	offered bool
}

// Reverse is the flow of the replies, nil until the censor has seen one
// of them. Both directions link each other.
func (f *Flow) Reverse() *Flow { return f.reverse }

// Payload is what the censor retained of the flow: a TCP stream's prefix,
// a UDP flow's first datagram. A module that keeps it clones it.
func (f *Flow) Payload() []byte {
	if f.Stream != nil {
		return f.Stream.Prefix()
	}
	return f.FirstDatagram
}

// retire stops passive module i of n seeing the flow.
func (f *Flow) retire(i, n int) {
	if f.done == nil {
		f.done = make([]bool, n)
	}
	f.done[i] = true
}

// observe counts a packet of the flow and adds its payload, and returns
// why it kept the payload out, "" when it didn't.
func (f *Flow) observe(p *Packet, now time.Time) string {
	f.Packets++
	f.Bytes += uint64(len(p.Payload))
	f.Last = now
	switch {
	case p.BadChecksum:
		return ignoreBadChecksum
	case f.Stream != nil:
		return f.Stream.add(p.Seq, p.Flags, p.Payload)
	case f.FirstDatagram == nil && len(p.Payload) > 0:
		f.FirstDatagram = append([]byte(nil), p.Payload[:min(len(p.Payload), retainBytes)]...)
	}
	return ""
}

func (f *Flow) snapshot(tagger, tag string) FlowSnapshot {
	return FlowSnapshot{
		Key: f.Key, Started: f.Started, Packets: f.Packets, Bytes: f.Bytes,
		Payload: append([]byte(nil), f.Payload()...), Tagger: tagger, Tag: tag,
	}
}

// FlowSnapshot is a copy of a flow handed to active modules, so they
// never share the flow table's Flow: once when the censor sees the flow's
// first packet, and once for each passive module that tags it.
type FlowSnapshot struct {
	Key     FlowKey
	Started time.Time
	Packets uint64
	Bytes   uint64
	// Payload is a copy of what the censor retained of the flow
	// (Flow.Payload) when the snapshot was taken.
	Payload []byte
	// Tagger and Tag are the passive module that tagged the flow and why;
	// both "" when the snapshot is of a new flow.
	Tagger, Tag string
}

// The flow table is unbounded: a censor runs for one lab test, whose
// traffic is a few thousand flows at most. Each flow keeps at most
// retainBytes of each kind of payload.
type flowTable struct {
	flows map[FlowKey]*Flow // the queue callback's alone

	// flags holds verdicts active modules pinned, from their own
	// goroutines, until the flow's next packet takes them.
	flagsMu sync.Mutex
	flags   map[FlowKey]rule

	// events has one channel per active module. publish runs in the
	// queue's serial callback, so it never waits: a snapshot the channel
	// has no room for is counted in unnoticed and not published, and the
	// module still sees the later ones once it has caught up.
	events    []chan FlowSnapshot
	eventsMu  sync.Mutex // guards closed against publish
	closed    bool
	unnoticed atomic.Uint64
}

func newFlowTable(active int) *flowTable {
	t := &flowTable{flows: map[FlowKey]*Flow{}, flags: map[FlowKey]rule{}}
	for i := 0; i < active; i++ {
		t.events = append(t.events, make(chan FlowSnapshot, 256))
	}
	return t
}

// flow finds the flow of a packet, creating it, linked to its reverse,
// when new.
func (t *flowTable) flow(key FlowKey, now time.Time) (*Flow, bool) {
	if f, ok := t.flows[key]; ok {
		return f, false
	}
	return t.fresh(key, now), true
}

// fresh puts a new flow in the table for key, in place of any old one,
// linked to the reverse the table has.
func (t *flowTable) fresh(key FlowKey, now time.Time) *Flow {
	f := &Flow{Key: key, Started: now, logged: map[ruleKey]bool{}, applied: map[Verdict]uint64{}}
	if key.Proto == ProtoTCP {
		f.Stream = &Stream{}
	}
	if r, ok := t.flows[key.Reverse()]; ok {
		f.reverse, r.reverse = r, f
	}
	t.flows[key] = f
	return f
}

// flag keeps an active module's verdict for the flow's next packet; of
// two flags, the more severe stays.
func (t *flowTable) flag(key FlowKey, r rule) {
	t.flagsMu.Lock()
	defer t.flagsMu.Unlock()
	if old, ok := t.flags[key]; !ok || r.severity() > old.severity() {
		t.flags[key] = r
	}
}

// takeFlag hands over the flag waiting for a flow, if any.
func (t *flowTable) takeFlag(key FlowKey) (rule, bool) {
	t.flagsMu.Lock()
	defer t.flagsMu.Unlock()
	r, ok := t.flags[key]
	delete(t.flags, key)
	return r, ok
}

// publish hands a snapshot to every active module that has room for it,
// without waiting; after closeEvents it does nothing.
func (t *flowTable) publish(snap FlowSnapshot) {
	if len(t.events) == 0 {
		return
	}
	t.eventsMu.Lock()
	defer t.eventsMu.Unlock()
	if t.closed {
		return
	}
	for _, ch := range t.events {
		select {
		case ch <- snap:
		default:
			t.unnoticed.Add(1)
		}
	}
}

// closeEvents closes every active module's channel, once.
func (t *flowTable) closeEvents() {
	t.eventsMu.Lock()
	defer t.eventsMu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	for _, ch := range t.events {
		close(ch)
	}
}

// flowEvents returns the channel for active module i.
func (t *flowTable) flowEvents(i int) <-chan FlowSnapshot { return t.events[i] }
