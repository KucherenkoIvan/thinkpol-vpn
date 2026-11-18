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
	// residual holds the 3-tuples blocked connections left blocked.
	residual map[residualKey]residualBlock
	// exempt holds the client flows an exemption passed, which the module
	// keeps seeing for residual censorship. Keyed by the Flow itself: a
	// connection that starts over on the same ports is judged afresh.
	exempt map[*Flow]bool
}

// residualCensorship is how long a blocked connection's 3-tuple stays
// blocked: Wu et al. (section 4.4) saw 120 or 180 seconds, the timer not
// reset by the packets it drops.
const residualCensorship = 180 * time.Second

// residualKey is Wu et al.'s 3-tuple, the client's address and the
// server's address and port, per protocol: the lab judges UDP too.
type residualKey struct {
	proto  Proto
	client netip.Addr
	server netip.AddrPort
}

func residualKeyOf(k FlowKey) residualKey {
	return residualKey{proto: k.Proto, client: k.Src, server: netip.AddrPortFrom(k.Dst, k.DstPort)}
}

type residualBlock struct {
	until time.Time
	// why names the connection blocked and why.
	why string
}

// newFullyEncrypted builds the module from its settings:
//
//	{"verdict": "drop", "tagOnly": false}
//
// with blockSettings' verdict (drop by default), rate and burst.
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
	return &fullyEncrypted{block: b, tagOnly: s.TagOnly, residual: map[residualKey]residualBlock{}, exempt: map[*Flow]bool{}}, nil
}

func (m *fullyEncrypted) Name() string { return "fully-encrypted" }

// Inspect judges a client flow's first data once, and drops its packets
// while a blocked connection's 3-tuple is under residual censorship: a
// connection that opens on it (its SYN, its first datagram) and one an
// exemption passed earlier alike, as the Great Firewall drops every
// packet of the 3-tuple. A tagging module blocks nothing, so it leaves no
// residual censorship either.
func (m *fullyEncrypted) Inspect(_ *Packet, f *Flow) Decision {
	if !f.Initiator() {
		return retired
	}
	if d, ok := m.residualDrop(f); ok {
		return d
	}
	if m.exempt[f] {
		return Decision{Verdict: Accept}
	}
	first := f.Payload()
	if len(first) == 0 {
		return Decision{Verdict: Accept}
	}
	why := looksFullyEncrypted(first)
	if why == "" {
		if m.tagOnly {
			return retired
		}
		m.exempt[f] = true
		return Decision{Verdict: Accept}
	}
	tag := "fully encrypted: " + why
	if m.tagOnly {
		return Decision{Verdict: Accept, Flow: true, Tag: tag}
	}
	d := m.block.decide(tag)
	d.Tag = tag
	m.residual[residualKeyOf(f.Key)] = residualBlock{
		until: f.Last.Add(residualCensorship),
		why:   fmt.Sprintf("%s was blocked (%s)", f.Key, tag),
	}
	return d
}

// residualDrop is the blocking decision for a packet of a client flow
// whose 3-tuple is under residual censorship, not pinned: once the time
// is up the flow is judged as any other. f.Last is the engine's clock at
// the packet, but for one with a bad checksum, which its receiver
// discards anyway.
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
	return m.block.decidePacket(fmt.Sprintf("residual censorship for %v: %s", residualCensorship, b.why)), true
}

// Wu et al.'s thresholds: random bytes average 4 set bits per byte.
const (
	exemptBitsLow, exemptBitsHigh = 3.4, 4.6
	exemptPrintablePrefix         = 6
	exemptPrintableRun            = 20
)

// looksFullyEncrypted applies Wu et al.'s exemptions to a connection's
// first data and says why none applies, "" when one does: (1) at most 3.4
// or at least 4.6 set bits per byte; (2) its first six bytes printable
// ASCII; (3) more than half of it printable; (4) a run of more than 20
// printable bytes; (5) a TLS record header or an HTTP request's method.
func looksFullyEncrypted(b []byte) string {
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
		return ""
	case len(b) >= exemptPrintablePrefix && allPrintable(b[:exemptPrintablePrefix]):
		return ""
	case printable*2 > len(b):
		return ""
	case longest > exemptPrintableRun:
		return ""
	case tlsOrHTTP(b):
		return ""
	}
	return fmt.Sprintf("%.2f set bits per byte, %d of %d bytes printable, longest printable run %d, no TLS or HTTP start",
		perByte, printable, len(b), longest)
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
