package lists

import (
	"net/netip"
	"testing"
)

func TestLocal(t *testing.T) {
	in := []string{
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
		"224.0.0.251", "239.255.255.250", "255.255.255.255", "fe80::1", "fd12::1", "fc00::1", "ff02::fb",
		"::ffff:192.168.1.1", // mapped addresses are looked up as IPv4
	}
	out := []string{
		"100.64.0.1", "100.127.255.255", // the overlay's range is never local
		"127.0.0.1", "::1", "0.0.0.0", "240.0.0.1", "172.32.0.1", "8.8.8.8", "2001:db8::1", "fec0::1",
	}
	for _, a := range in {
		if !Local().Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s is not local", a)
		}
	}
	for _, a := range out {
		if Local().Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s is local", a)
		}
	}
	if got := len(Local().Prefixes()); got != len(localPrefixes) {
		t.Errorf("%d prefixes, want %d (none of them merge)", got, len(localPrefixes))
	}
}

func TestAll(t *testing.T) {
	for _, a := range []string{"0.0.0.0", "255.255.255.255", "::", "::fffe:ffff:ffff", "::1:0:0:0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:1.2.3.4"} {
		if !All().Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s is not in All", a)
		}
	}
	for _, p := range All().Prefixes() {
		if p.Overlaps(netip.MustParsePrefix("::ffff:0:0/96")) {
			t.Errorf("All has %s, inside the mapped range", p)
		}
	}
	if left := All().Minus(Local()).Minus(All()); !left.IsEmpty() || len(left.Prefixes()) != 0 {
		t.Errorf("All minus All holds %v", left.Prefixes())
	}
	if All().IsEmpty() || Local().IsEmpty() || !(*Set)(nil).IsEmpty() || !(&Set{}).IsEmpty() {
		t.Error("IsEmpty is wrong")
	}
}
