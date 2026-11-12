package censor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
)

func init() {
	RegisterPassive("fully-encrypted", newFullyEncrypted)
}

// fullyEncrypted is the Great Firewall's passive detector of fully
// encrypted traffic (Wu et al., "How the Great Firewall of China Detects
// and Blocks Fully Encrypted Traffic", USENIX Security 2023): the first
// data a connection's client sends is blocked unless one of five
// exemptions says it isn't random-looking. Wu et al. saw it on TCP; the
// lab applies it to UDP's first datagram too.
type fullyEncrypted struct {
	block blocking
	// tagOnly: tag what it would block and let it through, for an active
	// module (the prober) to judge.
	tagOnly bool
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
	return &fullyEncrypted{block: b, tagOnly: s.TagOnly}, nil
}

func (m *fullyEncrypted) Name() string { return "fully-encrypted" }

func (m *fullyEncrypted) Inspect(_ *Packet, f *Flow) Decision {
	if !f.Initiator() {
		return retired
	}
	first := f.Payload()
	if len(first) == 0 {
		return Decision{Verdict: Accept}
	}
	why := looksFullyEncrypted(first)
	if why == "" {
		return retired
	}
	tag := "fully encrypted: " + why
	if m.tagOnly {
		return Decision{Verdict: Accept, Flow: true, Tag: tag}
	}
	d := m.block.decide(tag)
	d.Tag = tag
	return d
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
