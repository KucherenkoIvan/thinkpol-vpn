package ifbind

import "testing"

func TestTheFamilyComesFromTheNetwork(t *testing.T) {
	for network, want := range map[string]bool{"tcp4": false, "udp4": false, "tcp6": true, "udp6": true, "ip6:icmp": false} {
		got, err := isIPv6(network)
		if network == "ip6:icmp" {
			if err == nil {
				t.Errorf("%s: no error", network)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%s: %v, %v; want %v", network, got, err, want)
		}
	}
	for _, network := range []string{"", "tcp", "udp"} {
		if _, err := isIPv6(network); err == nil {
			t.Errorf("%q: no error", network)
		}
	}
}
