package dns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures in testdata/scutil are `scutil --dns` listings; no test
// runs scutil. Those named recorded-* are a Mac's (the 2026-10-24 device
// run), byte for byte but for the addresses and names, replaced by
// documentation ones (the router's resolver 192.0.2.1, the
// node's resolver 198.51.100.2 and 2001:db8:1::2, the overlay's domain
// example.net): before connecting, connected, and connected by the
// service right after a boot. The rest are built for what no device has
// printed: another VPN's supplemental resolver, no resolver at all, a
// line the parser can't place.
func scutilFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "scutil", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func resolverLines(rs []HostResolver) string {
	var out []string
	for _, r := range rs {
		out = append(out, fmt.Sprintf("scoped=%v if=%q servers=%v domains=%v search=%v order=%d options=%v flags=%q reach=%q",
			r.Scoped, r.Interface, r.Servers, r.Domains, r.Search, r.Order, r.Options, r.Flags, r.Reach))
	}
	return strings.Join(out, "\n")
}

func TestParseScutilDNS(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"recorded-dns-baseline.txt", []string{
			`scoped=false if="en0" servers=[192.0.2.1] domains=[] search=[] order=0 options=[] flags="Request A records" reach="0x00020002 (Reachable,Directly Reachable Address)"`,
			`scoped=false if="" servers=[] domains=[local] search=[] order=300000 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[254.169.in-addr.arpa] search=[] order=300200 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[8.e.f.ip6.arpa] search=[] order=300400 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[9.e.f.ip6.arpa] search=[] order=300600 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[a.e.f.ip6.arpa] search=[] order=300800 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[b.e.f.ip6.arpa] search=[] order=301000 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=true if="en0" servers=[192.0.2.1] domains=[] search=[] order=0 options=[] flags="Scoped, Request A records" reach="0x00020002 (Reachable,Directly Reachable Address)"`,
		}},
		{"recorded-dns-connected.txt", []string{
			`scoped=false if="" servers=[198.51.100.2 2001:db8:1::2] domains=[] search=[example.net] order=101400 options=[] flags="Supplemental, Request A records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=false if="en0" servers=[198.51.100.2] domains=[] search=[] order=200000 options=[] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[local] search=[] order=300000 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[254.169.in-addr.arpa] search=[] order=300200 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[8.e.f.ip6.arpa] search=[] order=300400 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[9.e.f.ip6.arpa] search=[] order=300600 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[a.e.f.ip6.arpa] search=[] order=300800 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[b.e.f.ip6.arpa] search=[] order=301000 options=[mdns] flags="Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=true if="en0" servers=[198.51.100.2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request A records" reach="0x00000000 (Not Reachable)"`,
			`scoped=true if="utun3" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=true if="utun2" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=true if="utun1" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=true if="utun0" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
		}},
		// An empty flags line ("flags    : "), as the mDNS resolvers had it then.
		{"recorded-dns-connected-at-boot.txt", []string{
			`scoped=false if="" servers=[198.51.100.2 2001:db8:1::2] domains=[] search=[] order=0 options=[] flags="Supplemental" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=false if="" servers=[] domains=[local] search=[] order=300000 options=[mdns] flags="" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[254.169.in-addr.arpa] search=[] order=300200 options=[mdns] flags="" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[8.e.f.ip6.arpa] search=[] order=300400 options=[mdns] flags="" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[9.e.f.ip6.arpa] search=[] order=300600 options=[mdns] flags="" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[a.e.f.ip6.arpa] search=[] order=300800 options=[mdns] flags="" reach="0x00000000 (Not Reachable)"`,
			`scoped=false if="" servers=[] domains=[b.e.f.ip6.arpa] search=[] order=301000 options=[mdns] flags="" reach="0x00000000 (Not Reachable)"`,
			`scoped=true if="utun1" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=true if="utun3" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=true if="utun2" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
			`scoped=true if="utun4" servers=[2001:db8:1::2] domains=[] search=[example.net] order=0 options=[] flags="Scoped, Request AAAA records" reach="0x00030002 (Reachable,Local Address,Directly Reachable Address)"`,
		}},
		{"dns-other-vpn.txt", []string{
			`scoped=false if="" servers=[100.64.0.2] domains=[] search=[lab.internal] order=100000 options=[] flags="Supplemental, Request A records, Request AAAA records" reach="0x00000002 (Reachable)"`,
			`scoped=false if="utun4" servers=[198.51.100.53] domains=[corp.example.net] search=[] order=102400 options=[] flags="Supplemental, Request A records" reach="0x00000003 (Reachable,Transient Connection)"`,
		}},
		{"dns-none.txt", nil},
	} {
		rs, err := parseScutilDNS(scutilFixture(t, tc.name))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := resolverLines(rs); got != strings.Join(tc.want, "\n") {
			t.Errorf("%s:\n%s\nwant:\n%s", tc.name, got, strings.Join(tc.want, "\n"))
		}
	}

	for in, want := range map[string]string{
		string(scutilFixture(t, "dns-unparseable.txt")):     "line 5: not a resolver's entry",
		"resolver #1\n  nameserver[0] : 192.0.2.1\n":        "line 1: a resolver before any section",
		"DNS configuration\n  nameserver[0] : 192.0.2.1\n":  "line 2: an entry outside a resolver",
		"DNS configuration\nresolver #1\n  if_index : 11\n": "line 3: an if_index without its interface",
		"DNS configuration\nresolver #1\n  order : high\n":  "line 3: an order that isn't a number",
	} {
		if rs, err := parseScutilDNS([]byte(in)); err == nil || !strings.Contains(err.Error(), want) || rs != nil {
			t.Errorf("%q: %v, %v; want %q", in, rs, err, want)
		}
	}
}

// TestInspectRunsScutilDNS runs Inspect on a stand-in for scutil, a
// script printing a fixture, never scutil itself.
func TestInspectRunsScutilDNS(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "scutil")
	fixture := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(fixture, scutilFixture(t, "dns-other-vpn.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n[ \"$*\" = --dns ] || { echo \"unexpected $*\" >&2; exit 2; }\ncat " + fixture + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	r := inspectWith(context.Background(), scutil{path: fake})
	if len(r.Sources) != 1 || r.Sources[0].Unreadable != "" || !r.Sources[0].Present || len(r.Sources[0].Resolvers) != 2 ||
		r.Sources[0].Resolvers[1].Interface != "utun4" {
		t.Fatalf("%+v", r)
	}
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho no >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if r := inspectWith(context.Background(), scutil{path: fake}); r.Sources[0].Unreadable == "" || r.Sources[0].Present {
		t.Fatalf("a failing scutil: %+v", r)
	}
}
