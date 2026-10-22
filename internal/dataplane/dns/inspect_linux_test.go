//go:build linux && !android

package dns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
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
	if src := inspectResolved(dbus.ConnectSystemBus, systemBusSocket); src.Present || src.Unreadable != "" || src.Name != "systemd-resolved" {
		t.Fatalf("%+v", src)
	}
	// A bus that is there but can't be reached is a failure to read it.
	sock := filepath.Join(t.TempDir(), "bus")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+sock)
	if src := inspectResolved(dbus.ConnectSystemBus, sock); src.Present || src.Unreadable == "" {
		t.Fatalf("an unreachable bus: %+v", src)
	}
}
