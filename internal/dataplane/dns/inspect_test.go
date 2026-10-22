package dns

import (
	"net/netip"
	"slices"
	"testing"
)

func TestResolvConfReport(t *testing.T) {
	original := []byte("# from DHCP\nnameserver 192.0.2.1\nnameserver 2001:db8::53\nsearch example.net\noptions edns0 trust-ad\n")
	r := resolvConfReport(original)
	if r.NodeWritten || !slices.Equal(r.Servers, []string{"192.0.2.1", "2001:db8::53"}) || !slices.Equal(r.Search, []string{"example.net"}) ||
		!slices.Equal(r.Options, []string{"edns0", "trust-ad"}) {
		t.Fatalf("the original: %+v", r)
	}
	// The node's rewrite: its resolver and search, the original's options,
	// the original in comments, which aren't read as the host's servers.
	r = resolvConfReport(render(SystemConfig{Servers: []netip.Addr{netip.MustParseAddr("100.64.0.2")}, Search: []string{"lab.internal"}}, original, ""))
	if !r.NodeWritten || !slices.Equal(r.Servers, []string{"100.64.0.2"}) || !slices.Equal(r.Search, []string{"lab.internal"}) ||
		!slices.Equal(r.Options, []string{"edns0", "trust-ad"}) {
		t.Fatalf("the node's: %+v", r)
	}
}
