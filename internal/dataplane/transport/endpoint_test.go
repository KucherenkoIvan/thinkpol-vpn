package transport_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/reality"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

// An endpoint is an IP literal and port, both set, read the same by every
// transport: udp and reality refuse the same endpoints. What it is (an
// endpoint, a target) is the caller's to say, once.
func TestParseEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:443":          "192.0.2.1:443",
		"[2001:db8::1]:4500":     "[2001:db8::1]:4500",
		"[::ffff:192.0.2.1]:443": "192.0.2.1:443",
	} {
		got, err := transport.ParseEndpoint(in)
		if err != nil || got != netip.MustParseAddrPort(want) {
			t.Errorf("%s: %v, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"192.0.2.1:0", "0.0.0.0:443", "[::]:443", "www.example.net:443", "192.0.2.1", ""} {
		if _, err := transport.ParseEndpoint(bad); err == nil || strings.Contains(err.Error(), "endpoint") {
			t.Errorf("%q: %v", bad, err)
		}
		if err := udp.New(udp.Options{}).CheckEndpoint(bad, transport.DialConfig{Credential: make([]byte, udp.MinSecretSize)}); err == nil || strings.Count(err.Error(), "endpoint") != 1 {
			t.Errorf("%q: udp says %v", bad, err)
		}
		if err := reality.New(reality.Options{}).CheckEndpoint(bad, transport.DialConfig{}); err == nil || strings.Count(err.Error(), "endpoint") != 1 {
			t.Errorf("%q: reality says %v", bad, err)
		}
	}
}
