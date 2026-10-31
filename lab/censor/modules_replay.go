package censor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"strconv"
	"time"
)

func init() {
	RegisterPassive("replay", newReplay)
}

// replay proves payload retention, tagging and a module that is passive
// and active at once, as block-ip proves the framework: its passive half
// tags each TCP flow to its destinations once the flow's stream holds a
// whole TLS record (a ClientHello, however many segments carried it), and
// its active half, given the tag, connects from the censor to the flow's
// destination and sends the retained bytes. It judges nothing; TP-026's
// prober is the real thing.
type replay struct {
	dests []netip.Prefix
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

// newReplay builds the module from its settings:
//
//	{"destinations": ["203.0.113.9", "2001:db8::/32"]}
func newReplay(settings json.RawMessage) (Passive, error) {
	var s struct {
		Destinations []string `json:"destinations"`
	}
	if err := json.Unmarshal(settings, &s); err != nil {
		return nil, err
	}
	dests, err := parseDestinations(s.Destinations)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &replay{dests: dests, dial: d.DialContext}, nil
}

func (m *replay) Name() string { return "replay" }

func (m *replay) Inspect(p *Packet, f *Flow) Decision {
	if f.Stream == nil || !contains(m.dests, p.Dst) || !wholeTLSRecord(f.Stream.Prefix()) {
		return Decision{Verdict: Accept}
	}
	return Decision{Verdict: Accept, Tag: "a whole TLS record"}
}

// wholeTLSRecord reports a stream that starts with a complete TLS
// handshake record.
func wholeTLSRecord(b []byte) bool {
	return len(b) >= 5 && b[0] == 0x16 && b[1] == 3 && len(b) >= 5+int(binary.BigEndian.Uint16(b[3:]))
}

func (m *replay) Run(ctx context.Context, flows <-chan FlowSnapshot, _ FlagFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-flows:
			if !ok {
				return
			}
			if f.Tagger == m.Name() {
				go m.replay(ctx, f)
			}
		}
	}
}

// replay sends a flow's retained bytes to its destination, as a client of
// its own.
func (m *replay) replay(ctx context.Context, f FlowSnapshot) {
	addr := net.JoinHostPort(f.Key.Dst.String(), strconv.Itoa(int(f.Key.DstPort)))
	c, err := m.dial(ctx, "tcp", addr)
	if err != nil {
		log.Printf("censor: replay %s: %v", f.Key, err)
		return
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(f.Payload); err != nil {
		log.Printf("censor: replay %s: %v", f.Key, err)
		return
	}
	log.Printf("censor: replay: sent %d bytes of %s to %s", len(f.Payload), f.Key, addr)
}
