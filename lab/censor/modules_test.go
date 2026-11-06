package censor

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBlockIPDropsByDestination(t *testing.T) {
	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.9", "2001:db8::/32"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{"203.0.113.9", "2001:db8::42"} {
		p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr(dst), 1, 2, []byte("x"))
		d := m.Inspect(p, &Flow{})
		if d.Verdict != Drop || !strings.Contains(d.Reason, dst) {
			t.Errorf("%s: %+v", dst, d)
		}
	}
	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("x"))
	if d := m.Inspect(p, &Flow{}); d.Verdict != Accept {
		t.Errorf("unrelated destination: %+v", d)
	}
}

func TestBlockIPSettings(t *testing.T) {
	for name, tc := range map[string]struct {
		settings string
		wantErr  string
	}{
		"no destinations": {`{}`, "no destinations"},
		"bad destination": {`{"destinations": ["999.1.1.1"]}`, "destination"},
		"bad verdict":     {`{"destinations": ["203.0.113.9"], "verdict": "poison"}`, "verdict"},
		"negative rate":   {`{"destinations": ["203.0.113.9"], "verdict": "throttle", "rate": -1}`, "rate"},
		"good throttle":   {`{"destinations": ["203.0.113.9"], "verdict": "throttle", "rate": 1750}`, ""},
		"good prefix":     {`{"destinations": ["203.0.113.0/24"]}`, ""},
	} {
		m, err := newBlockIP([]byte(tc.settings))
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want %q", name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if m.Name() != "block-ip" {
			t.Errorf("%s: name %q", name, m.Name())
		}
	}
}

func TestBlockIPThrottleRate(t *testing.T) {
	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.9"], "verdict": "throttle", "rate": 500, "burst": 900}`))
	if err != nil {
		t.Fatal(err)
	}
	p := udpPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9"), 1, 2, []byte("x"))
	d := m.Inspect(p, &Flow{})
	if d.Verdict != Throttle || d.Rate != 500 || d.Burst != 900 {
		t.Errorf("throttle decision %+v", d)
	}
}

// TestBlockIPDataOnly: with data, a packet without payload (the handshake)
// passes and the first one with payload is decided.
func TestBlockIPDataOnly(t *testing.T) {
	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.9"], "verdict": "reset", "data": true}`))
	if err != nil {
		t.Fatal(err)
	}
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9")
	if d := m.Inspect(tcpPacket(src, dst, 1, 2, 100, 0, Syn, nil), &Flow{}); d.Verdict != Accept {
		t.Errorf("SYN: %+v", d)
	}
	if d := m.Inspect(tcpPacket(src, dst, 1, 2, 101, 9, Ack|Psh, []byte("hi")), &Flow{}); d.Verdict != Reset {
		t.Errorf("data: %+v", d)
	}
}
