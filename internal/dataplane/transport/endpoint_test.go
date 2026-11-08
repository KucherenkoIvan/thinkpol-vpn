package transport_test

import (
	"net/netip"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/reality"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

// An endpoint is an IP literal and port, both set, read the same by every
// transport: udp and reality refuse the same endpoints.
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
		if _, err := transport.ParseEndpoint(bad); err == nil {
			t.Errorf("%q: parsed", bad)
		}
		if err := udp.New(udp.Options{}).CheckEndpoint(bad, transport.DialConfig{Credential: make([]byte, udp.MinSecretSize)}); err == nil {
			t.Errorf("%q: udp took it", bad)
		}
		if err := reality.New(reality.Options{}).CheckEndpoint(bad, transport.DialConfig{}); err == nil {
			t.Errorf("%q: reality took it", bad)
		}
	}
}
