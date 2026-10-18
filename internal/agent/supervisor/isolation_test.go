package supervisor

import (
	"net/netip"
	"testing"
)

// Public destinations pass the egress: only private, link-local and
// provider ranges are refused.
func TestPublicDestinationsPassTheEgress(t *testing.T) {
	for _, a := range []string{"9.9.9.9", "2620:fe::fe", "1.1.1.1", "2606:4700:4700::1111", "192.0.2.53", "2001:db8::53"} {
		if EgressRefused(netip.MustParseAddr(a), nil) {
			t.Errorf("%s refused", a)
		}
	}
}

// Private, link-local and metadata destinations are refused, the same
// ones the space_out chain drops, unless EgressAllowed names them; a
// zoned address is scoped to a link of the host's, and is refused.
func TestTheEgressRefusesWhatTheIsolationDropsUnlessAllowed(t *testing.T) {
	for _, a := range []string{
		"10.0.0.53", "192.168.1.53", "172.16.0.53", "100.100.100.200", "168.63.129.16",
		"169.254.169.254", "127.0.0.53", "224.0.0.1", "::ffff:192.0.2.1", "fd00::53", "fe80::1", "ff02::1",
		"fe80::1%eth0",
	} {
		if !EgressRefused(netip.MustParseAddr(a), nil) {
			t.Errorf("%s not refused", a)
		}
	}
	allowed := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fd00:ec2::/64")}
	if EgressRefused(netip.MustParseAddr("192.168.1.53"), allowed) {
		t.Errorf("an allowed prefix refused")
	}
	if EgressRefused(netip.MustParseAddr("fd00:ec2::254"), allowed) {
		t.Errorf("an allowed prefix refused")
	}
	if !EgressRefused(netip.MustParseAddr("10.0.0.53"), allowed) {
		t.Errorf("outside the allowed prefix not refused")
	}
	if !EgressRefused(netip.MustParseAddr("fd00::53"), allowed) {
		t.Errorf("another blocked range not refused")
	}
	if !EgressRefused(netip.MustParseAddr("fe80::1%eth0"), allowed) {
		t.Errorf("a zoned address not refused")
	}
}
