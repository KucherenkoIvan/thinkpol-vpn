//go:build linux && !android

package dns

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func TestInspectResolvConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if src := inspectResolvConf(path); src.Present || src.Unreadable != "" || src.Resolvers != nil {
		t.Fatalf("no file: %+v", src)
	}
	if err := os.WriteFile(path, []byte("nameserver 192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if src := inspectResolvConf(path); !src.Present || len(src.Resolvers) != 1 || src.Resolvers[0].Servers[0] != "192.0.2.1" {
		t.Fatalf("a file: %+v", src)
	}
	if src := inspectResolvConf(dir); src.Unreadable == "" || src.Present {
		t.Fatalf("a directory: %+v", src)
	}
}

// A lab node runs no D-Bus: there is no systemd-resolved, which is not
// a failure to read it.
func TestInspectResolvedWithoutABus(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	if src := inspectResolved(context.Background(), dbus.ConnectSystemBus, systemBusSocket); src.Present || src.Unreadable != "" || src.Name != "systemd-resolved" {
		t.Fatalf("%+v", src)
	}
	// A bus that is there but can't be reached is a failure to read it.
	sock := filepath.Join(t.TempDir(), "bus")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+sock)
	if src := inspectResolved(context.Background(), dbus.ConnectSystemBus, sock); src.Present || src.Unreadable == "" {
		t.Fatalf("an unreachable bus: %+v", src)
	}
}

func TestResolvedLinks(t *testing.T) {
	got, err := resolvedLinks(
		[]resolvedLinkAddr{{Ifindex: 0, Family: unix.AF_INET, Address: []byte{192, 0, 2, 53}}, {Ifindex: 1, Family: unix.AF_INET6, Address: netip.MustParseAddr("2001:db8::53").AsSlice()}},
		[]resolvedLinkDomain{{Ifindex: 1, Domain: ".", RoutingOnly: true}, {Ifindex: 1, Domain: "lab.internal"}},
	)
	if err != nil || len(got) != 2 || !slices.Equal(got[0].Servers, []string{"192.0.2.53"}) || got[0].Interface != "" ||
		!slices.Equal(got[1].Servers, []string{"2001:db8::53"}) || !slices.Equal(got[1].Domains, []string{"~.", "lab.internal"}) || got[1].Search != nil {
		t.Fatalf("%+v, %v", got, err)
	}
	if _, err := resolvedLinks([]resolvedLinkAddr{{Family: unix.AF_INET, Address: []byte{192, 0, 2}}}, nil); err == nil {
		t.Fatal("a three-byte address read")
	}
	if _, err := resolvedLinks([]resolvedLinkAddr{{Family: 99, Address: []byte{192, 0, 2, 1}}}, nil); err == nil {
		t.Fatal("an unknown family read")
	}
}
