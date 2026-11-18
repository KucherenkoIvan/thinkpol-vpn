package censor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/netip"
	"time"
)

func init() {
	RegisterPassive("fully-encrypted", newFullyEncrypted)
}

// fullyEncrypted is the Great Firewall's passive detector of fully
// encrypted traffic (Wu et al., "How the Great Firewall of China Detects
// and Blocks Fully Encrypted Traffic", USENIX Security 2023): the first
// data a connection's client sends is blocked unless one of five
// exemptions says it isn't random-looking, and then, as residual
// censorship, every packet its client sends to the server's address and
// port for a while. Wu et al. saw it on TCP; the lab applies it to UDP's
// first datagram too.
type fullyEncrypted struct {
	block blocking
	// tagOnly: tag what it would block and let it through, for an active
	// module (the prober) to judge.
	tagOnly bool
	// residual holds the 3-tuples blocked connections left blocked, per
	// protocol; pruned holds when its expired entries were last removed.
	residual map[residualKey]residualBlock
	pruned   time.Time
	// exempt holds the client flows an exemption passed, which the module
	// keeps seeing for residual censorship, one per FlowKey: a flow that
	// starts over on the same key (another Started) is judged afresh.
	exempt map[FlowKey]exemptFlow
}

type exemptFlow struct {
	started time.Time
	why     string
}

// residualCensorship is how long a blocked connection's 3-tuple stays
// blocked. Wu et al., section 4.4 (p. 2658): "it continues to drop all
// subsequent TCP packets having the same 3-tuple (client IP, server IP,
// server port) for 120 or 180 seconds", and "the GFW's residual
// censorship timer does not reset when additional packets are sent". The
// lab takes the longer, and never the shorter times they saw while many
// ports of one server were blocked at once (their Figure 2).
const residualCensorship = 180 * time.Second

// residualKey is Wu et al.'s 3-tuple, the client's address and the
// server's address and port, and the protocol the block covers: a TCP
// block covers TCP alone, since Wu et al. saw UDP "to or from the same
// (server IP, server Port)" unaffected by one; a UDP block, which they
// never saw, covers both (the lab's own, the stricter reading).
type residualKey struct {
	proto  Proto
	client netip.Addr
	server netip.AddrPort
}

func residualKeyOf(k FlowKey) residualKey {
	return residualKey{proto: k.Proto, client: k.Src, server: netip.AddrPortFrom(k.Dst, k.DstPort)}
}

type residualBlock struct {
	from, until time.Time
	// why names the connection blocked and why.
	why string
}

// newFullyEncrypted builds the module from its settings:
//
//	{"verdict": "drop", "tagOnly": false}
//
// with blockSettings' verdict (drop by default), rate and burst. The
// verdict is the blocked connection's; residual censorship always drops.
func newFullyEncrypted(settings json.RawMessage) (Passive, error) {
	var s struct {
		blockSettings
		TagOnly bool `json:"tagOnly"`
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	b, err := s.parse(Drop)
	if err != nil {
		return nil, err
	}
	return &fullyEncrypted{block: b, tagOnly: s.TagOnly, residual: map[residualKey]residualBlock{}, exempt: map[FlowKey]exemptFlow{}}, nil
}

func (m *fullyEncrypted) Name() string { return "fully-encrypted" }

// Inspect judges a client flow's first data once, and drops its packets
// while a blocked connection's 3-tuple is under residual censorship: a
// connection that opens on it (its SYN, its first datagram), as Wu et al.
// saw, and one an exemption passed before the block, the lab's own
// reading of their "all subsequent TCP packets". An exempt flow's Accept
// names its exemption and who opened the flow, for the verdict log. A
// tagging module blocks nothing, so it leaves no residual censorship
// either.
func (m *fullyEncrypted) Inspect(_ *Packet, f *Flow) Decision {
	if !f.Initiator() {
		return retired
	}
	if d, ok := m.residualDrop(f); ok {
		return d
	}
	if e, ok := m.exempt[f.Key]; ok && e.started.Equal(f.Started) {
		return Decision{Verdict: Accept, Reason: e.why}
	}
	first := f.Payload()
	if len(first) == 0 {
		return Decision{Verdict: Accept}
	}
	why, exempt := judgeFirstData(first)
	if exempt {
		if m.tagOnly {
			return retired
		}
		opener := "the side seen first"
		if f.Key.Proto == ProtoTCP {
			opener = "its SYN"
		}
		why = fmt.Sprintf("exempt: %s; opened by %s:%d (%s)", why, f.Key.Src, f.Key.SrcPort, opener)
		m.exempt[f.Key] = exemptFlow{started: f.Started, why: why}
		return Decision{Verdict: Accept, Reason: why}
	}
	tag := "fully encrypted: " + why
	if m.tagOnly {
		return Decision{Verdict: Accept, Flow: true, Tag: tag}
	}
	d := m.block.decide(tag)
	d.Tag = tag
	m.arm(f, tag)
	return d
}

// arm puts the blocked flow's 3-tuple under residual censorship, for TCP
// alone after a TCP block and for both protocols after a UDP one, and
// removes the expired 3-tuples at most once per residualCensorship, so
// the map holds no more than the blocks of the last two windows.
func (m *fullyEncrypted) arm(f *Flow, tag string) {
	now := f.Last
	if now.Sub(m.pruned) >= residualCensorship {
		for k, b := range m.residual {
			if !now.Before(b.until) {
				delete(m.residual, k)
			}
		}
		m.pruned = now
	}
	b := residualBlock{from: now, until: now.Add(residualCensorship), why: fmt.Sprintf("%s was blocked (%s)", f.Key, tag)}
	k := residualKeyOf(f.Key)
	m.residual[k] = b
	if k.proto == ProtoUDP {
		k.proto = ProtoTCP
		if old, ok := m.residual[k]; !ok || old.until.Before(b.until) {
			m.residual[k] = b
		}
	}
}

// residualDrop is the decision for a packet of a client flow whose
// 3-tuple is under residual censorship, a Drop whatever the module's
// verdict (a throttle or a reset would reach the server's direction, which
// residual censorship leaves alone), not pinned: once the time is up the
// flow is judged as any other. f.Last is the engine's clock at the packet,
// but for one with a bad checksum, which its receiver discards anyway.
func (m *fullyEncrypted) residualDrop(f *Flow) (Decision, bool) {
	k := residualKeyOf(f.Key)
	b, ok := m.residual[k]
	if !ok {
		return Decision{}, false
	}
	if !f.Last.Before(b.until) {
		delete(m.residual, k)
		return Decision{}, false
	}
	return Decision{Verdict: Drop, Reason: fmt.Sprintf("residual censorship of %s:%s from %s to %s: %s",
		k.client, k.server, b.from.UTC().Format(time.StampMilli), b.until.UTC().Format(time.StampMilli), b.why)}, true
}

// Wu et al.'s thresholds: random bytes average 4 set bits per byte.
const (
	exemptBitsLow, exemptBitsHigh = 3.4, 4.6
	exemptPrintablePrefix         = 6
	exemptPrintableRun            = 20
)

// judgeFirstData applies Wu et al.'s exemptions to a connection's first
// data, in their order: (1) at most 3.4 or at least 4.6 set bits per
// byte; (2) its first six bytes printable ASCII; (3) more than half of it
// printable; (4) a run of more than 20 printable bytes; (5) a TLS record
// header or an HTTP request's method. It says which passed it, or why none
// did.
func judgeFirstData(b []byte) (why string, exempt bool) {
	ones, printable, run, longest := 0, 0, 0, 0
	for _, c := range b {
		ones += bits.OnesCount8(c)
		if isPrintable(c) {
			printable++
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	perByte := float64(ones) / float64(len(b))
	switch {
	case perByte <= exemptBitsLow || perByte >= exemptBitsHigh:
		return fmt.Sprintf("%.2f set bits per byte, %d bytes", perByte, len(b)), true
	case len(b) >= exemptPrintablePrefix && allPrintable(b[:exemptPrintablePrefix]):
		return fmt.Sprintf("first six bytes printable, %d bytes", len(b)), true
	case printable*2 > len(b):
		return fmt.Sprintf("more than half printable, %d of %d bytes", printable, len(b)), true
	case longest > exemptPrintableRun:
		return fmt.Sprintf("a printable run of %d bytes, %d bytes", longest, len(b)), true
	case tlsOrHTTP(b):
		return fmt.Sprintf("a TLS or HTTP start, %d bytes", len(b)), true
	}
	return fmt.Sprintf("%.2f set bits per byte, %d of %d bytes printable, longest printable run %d, no TLS or HTTP start",
		perByte, printable, len(b), longest), false
}

func isPrintable(c byte) bool { return c >= 0x20 && c <= 0x7e }

func allPrintable(b []byte) bool {
	for _, c := range b {
		if !isPrintable(c) {
			return false
		}
	}
	return true
}

// tlsOrHTTP is Wu et al.'s fifth exemption: a TLS record header (handshake
// or application data, version 3.0 to 3.9) or an HTTP request's method.
func tlsOrHTTP(b []byte) bool {
	if len(b) >= 3 && (b[0] == 0x16 || b[0] == 0x17) && b[1] == 3 && b[2] <= 9 {
		return true
	}
	for _, method := range []string{"GET ", "PUT ", "POST ", "HEAD "} {
		if bytes.HasPrefix(b, []byte(method)) {
			return true
		}
	}
	return false
}
