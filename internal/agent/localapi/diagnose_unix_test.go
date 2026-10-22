//go:build unix

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

const testVersion = "v0.0.0-test"

func TestDiagnoseServesAVersionedSnapshot(t *testing.T) {
	s := serve(t, me())
	c := dial(t, s.socket)
	ctx := context.Background()
	s.node.diag.TUN = agent.InterfaceReport{Name: "utun9", Index: 21, MTU: 1328, Up: true, Running: true,
		Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/10"), netip.MustParsePrefix("fd00:1:2::2/48")}}
	before := time.Now()
	d, err := c.Diagnose(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.GetSchemaVersion() != DiagSchemaVersion || d.GetOs() != runtime.GOOS || d.GetAgentVersion() != testVersion ||
		d.GetTakenAt().AsTime().Before(before.Truncate(time.Second)) {
		t.Fatalf("header: %v", d)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(d.GetStatus(), st) {
		t.Fatalf("the snapshot's status %v, GetStatus %v", d.GetStatus(), st)
	}
	want := &localapiv1.DiagInterface{Name: "utun9", Index: 21, Mtu: 1328, Up: true, Running: true,
		Addresses: []string{"100.64.0.2/10", "fd00:1:2::2/48"}}
	if !proto.Equal(d.GetTun(), want) {
		t.Fatalf("TUN %v, want %v", d.GetTun(), want)
	}

	// As `thinkpol diag` prints it: JSON a script reads, version first.
	var out bytes.Buffer
	if err := WriteJSON(&out, d); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		SchemaVersion int `json:"schemaVersion"`
		Tun           struct {
			Name string `json:"name"`
		} `json:"tun"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil || parsed.SchemaVersion != DiagSchemaVersion || parsed.Tun.Name != "utun9" {
		t.Fatalf("JSON %+v, %v:\n%s", parsed, err, out.String())
	}

	// A part the agent couldn't read says why, and holds nothing else.
	s.node.mu.Lock()
	s.node.diag.TUN = agent.InterfaceReport{Unreadable: agent.UnreadableNoTUN, Name: "stale", MTU: 1}
	s.node.mu.Unlock()
	if d, err = c.Diagnose(ctx); err != nil || !proto.Equal(d.GetTun(), &localapiv1.DiagInterface{Unreadable: agent.UnreadableNoTUN}) {
		t.Fatalf("an unreadable TUN: %v, %v", d.GetTun(), err)
	}
}

// secretName is what a field holding a secret would be called.
var secretName = regexp.MustCompile(`(?i)key|token|secret|session|password|passphrase|credential|private|psk|cookie|seed`)

// TestTheSnapshotHasNoSecretField walks the snapshot's schema, the status
// it carries included: no field may be named for a key, a token, a
// session or a credential, so one can't be added by accident. Endpoints
// and addresses are allowed (the user reads them).
func TestTheSnapshotHasNoSecretField(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	fields := 0
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		for i := range md.Fields().Len() {
			fd := md.Fields().Get(i)
			fields++
			if secretName.MatchString(string(fd.Name())) {
				t.Errorf("%s holds %q", md.FullName(), fd.Name())
			}
			if fd.IsMap() {
				fd = fd.MapValue()
			}
			if fd.Message() != nil {
				walk(fd.Message())
			}
		}
	}
	walk((&localapiv1.Diagnostics{}).ProtoReflect().Descriptor())
	if !seen[(&localapiv1.Status{}).ProtoReflect().Descriptor().FullName()] || fields < 50 {
		t.Fatalf("walked %d fields of %d messages", fields, len(seen))
	}
}

func TestWriteJSONFileIsTheOwnersOnly(t *testing.T) {
	dir := t.TempDir()
	d := &localapiv1.Diagnostics{SchemaVersion: DiagSchemaVersion, Os: "linux"}
	path := filepath.Join(dir, "diag.json")
	check := func(t *testing.T) {
		t.Helper()
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%v, %v", fi.Mode(), err)
		}
		b, _ := os.ReadFile(path)
		var got struct {
			SchemaVersion int `json:"schemaVersion"`
		}
		if err := json.Unmarshal(b, &got); err != nil || got.SchemaVersion != DiagSchemaVersion {
			t.Fatalf("%s: %v", b, err)
		}
	}

	if err := WriteJSONFile(path, d); err != nil {
		t.Fatal(err)
	}
	check(t)

	// A file there already, open to all, is replaced by one that isn't.
	if err := os.WriteFile(path, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFile(path, d); err != nil {
		t.Fatal(err)
	}
	check(t)

	// A symlink there is replaced, its target left alone: root writing
	// into a directory others can write to never follows their link.
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFile(path, d); err != nil {
		t.Fatal(err)
	}
	check(t)
	if b, _ := os.ReadFile(target); string(b) != "theirs" {
		t.Fatalf("the link's target now holds %q", b)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("left behind: %v", entries)
	}
	if err := WriteJSONFile(filepath.Join(dir, "no-such-dir", "diag.json"), d); err == nil {
		t.Fatal("wrote into a directory that doesn't exist")
	}
}

func TestDiagnoseCarriesTheHostParts(t *testing.T) {
	s := serve(t, me())
	c := dial(t, s.socket)
	ctx := context.Background()
	pfx := netip.MustParsePrefix
	s.node.mu.Lock()
	s.node.diag.Routes = netcfg.Inspection{
		Routes: []netcfg.HostRoute{
			{Owner: netcfg.OwnerRouteTable, Family: netcfg.IPv4, Dst: pfx("198.51.100.0/24"), Type: "throw", Table: 29808},
			{Owner: netcfg.OwnerOverlay, Family: netcfg.IPv6, Dst: pfx("fd00:1:2::/48"), Type: "unicast", Interface: "thinkpol0", Metric: 1024, Table: 254,
				Gateway: netip.MustParseAddr("fe80::1")},
		},
		Rules: []netcfg.HostRule{{Owner: netcfg.OwnerRouteTable, Family: netcfg.IPv4, Priority: 5301, Table: 29808, Mark: 0x7470, Mask: 0xffffffff,
			Invert: true, SuppressPrefixlen: -1}},
	}
	s.node.diag.DNS = dns.HostReport{Sources: []dns.HostSource{
		{Name: "resolv.conf", Present: true, Resolvers: []dns.HostResolver{{Servers: []string{"100.64.0.2"}, Search: []string{"lab.internal"}, Options: []string{"edns0"}, NodeWritten: true}}},
		{Name: "systemd-resolved", Unreadable: "the system bus: refused", Present: true, Resolvers: []dns.HostResolver{{Servers: []string{"192.0.2.53"}}}},
		{Name: "scutil --dns", Present: true, Resolvers: []dns.HostResolver{{Interface: "en0", Scoped: true, Servers: []string{"192.0.2.1"}, Domains: []string{"local"},
			Order: 300000, Flags: "Scoped", Reach: "0x00000002 (Reachable)"}}},
	}}
	s.node.diag.Guard = routetable.GuardReport{
		Where: "nftables table inet thinkpol-guard", Present: true,
		Rules:    []routetable.GuardRuleReport{{Chain: "output", Text: "counter reject with icmpx admin-prohibited", Counted: true, Packets: 3, Bytes: 312}},
		Exempt:   []netip.Prefix{pfx("2001:db8:d0::/48")},
		NFTables: &routetable.NFTablesReport{Chains: []routetable.NFTChainReport{{Name: "output", Hook: "output", Priority: 2147483647, Policy: "accept"}}},
	}
	s.node.mu.Unlock()

	d, err := c.Diagnose(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h := s.node.askedHost(); h == nil || !*h {
		t.Fatal("the service's own user wasn't given the host parts")
	}
	wantRoutes := &localapiv1.DiagRoutes{Routes: []*localapiv1.DiagRoute{
		{Owner: "route-table", Family: "IPv4", Destination: "198.51.100.0/24", Type: "throw", Table: 29808},
		{Owner: "overlay", Family: "IPv6", Destination: "fd00:1:2::/48", Type: "unicast", Gateway: "fe80::1", Interface: "thinkpol0", Metric: 1024, Table: 254},
	}}
	wantRules := &localapiv1.DiagRules{Rules: []*localapiv1.DiagRule{{Owner: "route-table", Family: "IPv4", Priority: 5301, Table: 29808,
		Mark: 0x7470, Mask: 0xffffffff, Invert: true, SuppressPrefixlen: -1}}}
	wantGuard := &localapiv1.DiagGuard{
		Where: "nftables table inet thinkpol-guard", Present: true,
		Rules: &localapiv1.DiagGuardRules{Rules: []*localapiv1.DiagGuardRule{{Chain: "output", Text: "counter reject with icmpx admin-prohibited",
			Counted: true, Packets: 3, Bytes: 312}}},
		Exempt:   &localapiv1.DiagPrefixes{Prefixes: []string{"2001:db8:d0::/48"}},
		Nftables: &localapiv1.DiagNftables{Chains: []*localapiv1.DiagNftChain{{Name: "output", Hook: "output", Priority: 2147483647, Policy: "accept"}}},
	}
	wantDNS := &localapiv1.DiagDns{Sources: []*localapiv1.DiagDnsSource{
		{Name: "resolv.conf", Present: true, Resolvers: []*localapiv1.DiagResolver{{Servers: []string{"100.64.0.2"}, Search: []string{"lab.internal"}, Options: []string{"edns0"}, NodeWritten: true}}},
		{Name: "systemd-resolved", Unreadable: "the system bus: refused"},
		{Name: "scutil --dns", Present: true, Resolvers: []*localapiv1.DiagResolver{{Interface: "en0", Scoped: true, Servers: []string{"192.0.2.1"}, Domains: []string{"local"},
			Order: 300000, Flags: "Scoped", Reach: "0x00000002 (Reachable)"}}},
	}}
	for what, pair := range map[string][2]proto.Message{
		"routes": {d.GetRoutes(), wantRoutes}, "rules": {d.GetRules(), wantRules}, "guard": {d.GetGuard(), wantGuard}, "dns": {d.GetDns(), wantDNS},
	} {
		if !proto.Equal(pair[0], pair[1]) {
			t.Errorf("%s: %v, want %v", what, pair[0], pair[1])
		}
	}

	// Parts that couldn't be read say why and hold nothing else; a guard
	// the host doesn't hold is only where it would be.
	s.node.mu.Lock()
	s.node.diag.Routes.RoutesUnreadable, s.node.diag.Routes.RulesUnreadable = "netlink: permission denied", "netlink: permission denied"
	s.node.diag.Guard.RulesUnreadable, s.node.diag.Guard.ExemptUnreadable = "nftables rules: EPERM", "nftables set: EPERM"
	s.node.mu.Unlock()
	if d, err = c.Diagnose(ctx); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(d.GetRoutes(), &localapiv1.DiagRoutes{Unreadable: "netlink: permission denied"}) ||
		!proto.Equal(d.GetRules(), &localapiv1.DiagRules{Unreadable: "netlink: permission denied"}) ||
		!proto.Equal(d.GetGuard().GetRules(), &localapiv1.DiagGuardRules{Unreadable: "nftables rules: EPERM"}) ||
		!proto.Equal(d.GetGuard().GetExempt(), &localapiv1.DiagPrefixes{Unreadable: "nftables set: EPERM"}) {
		t.Fatalf("unreadable parts: %v", d)
	}
	s.node.mu.Lock()
	s.node.diag.Guard = routetable.GuardReport{Where: "nftables table inet thinkpol-guard", Rules: s.node.diag.Guard.Rules}
	s.node.mu.Unlock()
	if d, err = c.Diagnose(ctx); err != nil || !proto.Equal(d.GetGuard(), &localapiv1.DiagGuard{Where: "nftables table inet thinkpol-guard"}) {
		t.Fatalf("no guard: %v, %v", d.GetGuard(), err)
	}
	// macOS after a stop: no rules, but pf's state and a reference that
	// pf no longer lists (unreadable listing: held not claimed).
	s.node.mu.Lock()
	s.node.diag.Guard = routetable.GuardReport{Where: "pf anchor com.apple/000.thinkpol", PF: &routetable.PFReport{
		Enabled: true, Hook: "bypassed", Skipped: []string{"en0"}, AnchorsBefore: []string{"com.apple/0.other"},
		Reference: &routetable.PFReferenceReport{Recorded: true, Pid: 4130, Held: true, HeldUnreadable: "pfctl -s References: odd"},
	}}
	s.node.mu.Unlock()
	wantPf := &localapiv1.DiagGuard{Where: "pf anchor com.apple/000.thinkpol", Pf: &localapiv1.DiagPf{
		Enabled:   &localapiv1.DiagPfEnabled{Enabled: true},
		Hook:      &localapiv1.DiagPfHook{State: "bypassed", Skipped: []string{"en0"}, AnchorsBefore: []string{"com.apple/0.other"}},
		Reference: &localapiv1.DiagPfReference{HeldUnreadable: "pfctl -s References: odd", Recorded: true, Pid: 4130},
	}}
	if d, err = c.Diagnose(ctx); err != nil || !proto.Equal(d.GetGuard(), wantPf) {
		t.Fatalf("pf: %v, %v", d.GetGuard(), err)
	}
	// A record that can't be read: unreadable, and nothing else.
	s.node.mu.Lock()
	s.node.diag.Guard.PF.ReferenceUnreadable = "trusteddir: permission denied"
	s.node.mu.Unlock()
	if d, err = c.Diagnose(ctx); err != nil || !proto.Equal(d.GetGuard().GetPf().GetReference(), &localapiv1.DiagPfReference{Unreadable: "trusteddir: permission denied"}) {
		t.Fatalf("an unreadable record: %v, %v", d.GetGuard().GetPf(), err)
	}
	s.node.mu.Lock()
	s.node.diag.Guard = routetable.GuardReport{Where: "pf anchor com.apple/000.thinkpol", Unreadable: "no pfctl", Present: true}
	s.node.mu.Unlock()
	if d, err = c.Diagnose(ctx); err != nil || !proto.Equal(d.GetGuard(), &localapiv1.DiagGuard{Where: "pf anchor com.apple/000.thinkpol", Unreadable: "no pfctl"}) {
		t.Fatalf("an unreadable guard: %v, %v", d.GetGuard(), err)
	}
}
