package supervisor

import (
	"net/netip"
	"testing"
)

// The well-known public resolvers are never destinations the egress
// refuses: an exit's default upstreams must pass the same check its
// packets do.
func TestTheDefaultUpstreamAddressesPassTheEgress(t *testing.T) {
	for _, a := range []string{"9.9.9.9", "2620:fe::fe", "1.1.1.1", "2606:4700:4700::1111", "192.0.2.53", "2001:db8::53"} {
		if EgressRefused(netip.MustParseAddr(a), nil) {
			t.Errorf("%s refused", a)
		}
	}
}

// Private, link-local and metadata destinations are refused, the same
// ones the space_out chain drops, unless EgressAllowed names them.
func TestTheEgressRefusesWhatTheIsolationDropsUnlessAllowed(t *testing.T) {
	for _, a := range []string{
		"10.0.0.53", "192.168.1.53", "172.16.0.53", "100.100.100.200", "168.63.129.16",
		"169.254.169.254", "127.0.0.53", "224.0.0.1", "::ffff:192.0.2.1", "fd00::53", "fe80::1", "ff02::1",
	} {
		if !EgressRefused(netip.MustParseAddr(a), nil) {
			t.Errorf("%s not refused", a)
		}
	}
	allowed := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("2001:db8:f00d::/48")}
	if EgressRefused(netip.MustParseAddr("192.168.1.53"), allowed) {
		t.Errorf("an allowed prefix refused")
	}
	if EgressRefused(netip.MustParseAddr("2001:db8:f00d::53"), allowed) {
		t.Errorf("an allowed prefix refused")
	}
	if !EgressRefused(netip.MustParseAddr("10.0.0.53"), allowed) {
		t.Errorf("outside the allowed prefix not refused")
	}
	if !EgressRefused(netip.MustParseAddr("fd00::53"), allowed) {
		t.Errorf("another blocked range not refused")
	}
}
