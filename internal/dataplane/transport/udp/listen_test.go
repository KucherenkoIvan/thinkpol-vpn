package udp

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

func TestListenBindsOneFamily(t *testing.T) {
	for addr, want := range map[string]string{
		"0.0.0.0:4500":            "udp4",
		"192.0.2.1:4500":          "udp4",
		"[::ffff:192.0.2.1]:4500": "udp4",
		"[::]:4500":               "udp6",
		"[2001:db8::1]:4500":      "udp6",
	} {
		if got := listenNetwork(netip.MustParseAddrPort(addr)); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
}

// A dual-stack node's map has a listener per family on the same port; both
// must bind. Wildcard addresses, so only in the lab.
func TestListenWildcardsOfBothFamiliesOnOnePort(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	ctx := context.Background()
	tr := New(Options{})
	peers := transport.NewPeerTable()
	v4, err := tr.Listen(ctx, transport.ListenConfig{Address: "0.0.0.0:0", Peers: peers})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v4.Close() }()
	port := netip.MustParseAddrPort(v4.Addr().String()).Port()
	v6, err := tr.Listen(ctx, transport.ListenConfig{Address: netip.AddrPortFrom(netip.IPv6Unspecified(), port).String(), Peers: peers})
	if err != nil {
		t.Fatalf("[::]:%d next to 0.0.0.0:%d: %v", port, port, err)
	}
	_ = v6.Close()
}
