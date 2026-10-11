package ipc_test

import (
	"net/netip"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
)

func TestInitRoundTrip(t *testing.T) {
	in := ipc.Init{
		Space:     "00112233445566778899aabbccddeeff",
		Interface: "veth0",
		Addrs:     []netip.Prefix{netip.MustParsePrefix("169.254.100.2/30"), netip.MustParsePrefix("fd74:7470::2/64")},
		Gateways:  []netip.Addr{netip.MustParseAddr("169.254.100.1"), netip.MustParseAddr("fd74:7470::1")},
		Version:   1, UID: 1000, GID: 1001,
	}
	m, err := ipc.InitMessage(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ipc.DecodeInit(m)
	if err != nil {
		t.Fatal(err)
	}
	if out.Space != in.Space || out.Interface != in.Interface || out.UID != in.UID || out.GID != in.GID ||
		len(out.Addrs) != 2 || out.Addrs[1] != in.Addrs[1] || out.Gateways[0] != in.Gateways[0] {
		t.Fatalf("round trip: %+v, want %+v", out, in)
	}
	if _, err := ipc.DecodeInit(ipc.Message{Kind: ipc.KindReady}); err == nil {
		t.Fatal("decoded a ready message as init")
	}
}
