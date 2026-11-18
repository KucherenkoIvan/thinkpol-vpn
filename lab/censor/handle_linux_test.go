//go:build linux

package censor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestHandledAfterItsEntries: the watermark that covers a queued packet
// comes after the packet's decision even when the log flushes while the
// engine decides it (here at every read of the engine's clock), so a
// reader that waited for the watermark has the decision.
func TestHandledAfterItsEntries(t *testing.T) {
	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.9"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	eng := NewEngine([]Passive{m}, nil, &buf)
	eng.now = func() time.Time {
		eng.log.flush()
		return time.Now()
	}
	var got Verdict
	handlePacket(eng, nil, 7, rawUDP(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9"), []byte("x")), func(v Verdict) { got = v })
	eng.Shutdown()
	if got != Drop {
		t.Errorf("the verdict: %v, want drop", got)
	}
	var events []string
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		if e.Event == EventDecision || e.Event == EventWatermark {
			events = append(events, e.Event)
		}
	}
	if strings.Join(events, ", ") != EventDecision+", "+EventWatermark {
		t.Errorf("the log's decisions and watermarks: %q, want the decision first:\n%s", events, buf.String())
	}
}

// rawUDP is an IPv4 UDP packet as the queue hands it over.
func rawUDP(src, dst netip.Addr, payload []byte) []byte {
	b := make([]byte, 20+8+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, byte(ProtoUDP)
	copy(b[12:], src.AsSlice())
	copy(b[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(b[20:], 40000)
	binary.BigEndian.PutUint16(b[22:], 4500)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}
