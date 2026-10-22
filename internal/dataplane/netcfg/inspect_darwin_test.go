package netcfg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func inspectedLines(in Inspection) []string {
	var out []string
	for _, r := range in.Routes {
		s := fmt.Sprintf("%v %v %s %s", r.Owner, r.Family, r.Type, r.Dst)
		if r.Gateway.IsValid() {
			s += " via " + r.Gateway.String()
		}
		if r.Interface != "" {
			s += " dev " + r.Interface
		}
		if r.Scope != "" {
			s += " scope " + r.Scope
		}
		out = append(out, s)
	}
	return out
}

// TestInspectReadsTheRecordedRoutes: the routes the owners' records name
// and the kernel holds with routeFlag, nothing else of anyone's; a
// directory not made yet holds none; a corrupt record is unreadable, not
// empty.
func TestInspectReadsTheRecordedRoutes(t *testing.T) {
	k, dir := newFakeKernel(), tempDir(t)
	if in := inspectDarwin(k, filepath.Join(dir, "not-yet")); in.RoutesUnreadable != "" || len(in.Routes) != 0 || len(in.Rules) != 0 {
		t.Fatalf("no directory: %+v", in)
	}
	if _, err := os.Stat(filepath.Join(dir, "not-yet")); !os.IsNotExist(err) {
		t.Fatalf("inspecting made the directory: %v", err)
	}
	ctx := context.Background()
	if err := newTestConfigurator(t, k, dir, OwnerOverlay).Apply(ctx, overlayConfig); err != nil {
		t.Fatal(err)
	}
	// Split routes, an endpoint's and a direct route, by the fake host's
	// gateways.
	split := Config{Routes: []Route{
		{Dst: pfx("0.0.0.0/1"), Interface: "utun7"},
		{Dst: pfx("128.0.0.0/1"), Interface: "utun7"},
		{Dst: pfx("::/1"), Type: RouteUnreachable},
		{Dst: pfx("8000::/1"), Type: RouteUnreachable},
		{Dst: pfx("203.0.113.9/32"), Gateway: ip("192.168.1.1")},
		{Dst: pfx("2001:db8::/32"), Gateway: ip("fe80::1"), Interface: "en0"},
	}}
	if err := newTestConfigurator(t, k, dir, OwnerRouteTable).Apply(ctx, split); err != nil {
		t.Fatal(err)
	}
	// Someone else's route with routeFlag, in no record.
	k.mu.Lock()
	k.rs[pfx("198.51.100.0/24")] = kroute{dst: pfx("198.51.100.0/24"), gw: ip("192.168.1.1"), index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | routeFlag}
	k.mu.Unlock()

	in := inspectDarwin(k, dir)
	if in.RoutesUnreadable != "" || in.RulesUnreadable != "" || len(in.Rules) != 0 {
		t.Fatalf("%+v", in)
	}
	// Someone else's RTF_PROTO2 route is shown apart; the kernel's clone
	// carrying the flag isn't a route at all.
	if u := in.UnrecordedProto2; len(u) != 1 || u[0].Dst != pfx("198.51.100.0/24") || u[0].Owner != 0 || u[0].Gateway != ip("192.168.1.1") {
		t.Fatalf("unrecorded %+v", u)
	}
	got := strings.Join(inspectedLines(in), "\n")
	want := strings.Join([]string{
		"route-table IPv4 unicast 0.0.0.0/1 dev utun7",
		"overlay IPv4 unicast 100.64.0.0/11 dev utun7",
		"overlay IPv4 unicast 100.96.0.0/11 dev utun7",
		"route-table IPv4 unicast 128.0.0.0/1 dev utun7",
		"route-table IPv4 unicast 203.0.113.9/32 via 192.168.1.1",
		"route-table IPv6 unreachable ::/1 via ::1", // a reject route's loopback gateway
		"route-table IPv6 unicast 2001:db8::/32 via fe80::1 dev en0",
		"route-table IPv6 unreachable 8000::/1 via ::1",
		"overlay IPv6 unicast fd12:3456:789a::/49 dev utun7",
		"overlay IPv6 unicast fd12:3456:789a:8000::/49 dev utun7",
	}, "\n")
	if got != want {
		t.Fatalf("routes:\n%s\nwant:\n%s", got, want)
	}

	if err := os.WriteFile(filepath.Join(dir, recordName(OwnerOverlay)), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if in := inspectDarwin(k, dir); !strings.Contains(in.RoutesUnreadable, "overlay's route record") || in.Routes != nil {
		t.Fatalf("a corrupt record: %+v", in)
	}
}
