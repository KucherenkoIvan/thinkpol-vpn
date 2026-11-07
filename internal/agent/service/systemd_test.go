//go:build linux || darwin

package service

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The unit's drop-ins are listed from every directory systemd reads,
// *.conf only, a directory reached twice (/lib as a link to /usr/lib)
// once; one that can't be read makes the report say so.
func TestDropInsAreListed(t *testing.T) {
	root := t.TempDir()
	file := func(path string) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("[Service]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if r := dropIns(root); r.Unreadable != "" || len(r.Paths) != 0 {
		t.Fatalf("no unit directories: %+v", r)
	}
	file("etc/systemd/system/thinkpol.service.d/override.conf")
	file("etc/systemd/system/thinkpol.service.d/notes.txt")
	file("etc/systemd/system/other.service.d/other.conf")
	file("etc/systemd/system/service.d/every-service.conf")
	file("usr/lib/systemd/system/thinkpol.service.d/vendor.conf")
	// What `systemctl set-property thinkpol.service CPUQuota=50%` writes.
	file("etc/systemd/system.control/thinkpol.service.d/50-CPUQuota.conf")
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/etc/systemd/system.control/thinkpol.service.d/50-CPUQuota.conf",
		"/etc/systemd/system/thinkpol.service.d/override.conf",
		"/etc/systemd/system/service.d/every-service.conf",
		"/usr/lib/systemd/system/thinkpol.service.d/vendor.conf",
	}
	if r := dropIns(root); r.Unreadable != "" || !slices.Equal(r.Paths, want) {
		t.Fatalf("got %+v, want %q", r, want)
	}

	if os.Geteuid() == 0 {
		t.Skip("root reads a directory of mode 0")
	}
	locked := filepath.Join(root, "etc/systemd/system/thinkpol.service.d")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if r := dropIns(root); !strings.Contains(r.Unreadable, "/etc/systemd/system/thinkpol.service.d") || len(r.Paths) != 0 {
		t.Fatalf("an unreadable directory: %+v", r)
	}
	// Directories that can't even be resolved are each reported.
	file("run/systemd/transient/thinkpol.service.d/transient.conf")
	for _, d := range []string{"etc/systemd/system.control", "run/systemd/transient"} {
		locked := filepath.Join(root, d)
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	}
	r := dropIns(root)
	for _, d := range []string{"/etc/systemd/system.control/thinkpol.service.d", "/run/systemd/transient/thinkpol.service.d"} {
		if !strings.Contains(r.Unreadable, d+":") {
			t.Errorf("%s not reported: %+v", d, r)
		}
	}
}
