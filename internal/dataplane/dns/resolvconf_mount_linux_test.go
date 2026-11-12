//go:build linux && !android

package dns

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// On a bind mount the node rewrites resolv.conf in place, as another
// program would. The watch reads the file under the lock an apply holds,
// so it never finds the node's own write half done: no settle begins,
// every Update is written at once, and nothing is told.
func TestResolvConfOwnInPlaceWritesOnABindMountStartNoSettle(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	dir := t.TempDir()
	source, path := filepath.Join(dir, "source.conf"), filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(source, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, path, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind mount: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(path, 0) })

	var log lockedBuffer
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams = func(a []netip.Addr) { told <- a }
	c.Log = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// A settle that began would hold every later Update for an hour; the
	// watch reads the file every millisecond, so it reads often while an
	// apply writes.
	r, err := setResolvConfTimed(path, "", c, resolvConfTiming{check: time.Millisecond, settle: time.Hour, settleMax: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	for i := range 500 {
		next := c
		next.Search = []string{"zone" + string(rune('a'+i%26)) + ".internal"}
		if err := r.Update(next); err != nil {
			t.Fatal(err)
		}
		if got := readString(t, path); !strings.Contains(got, "\nsearch "+next.Search[0]+"\n") {
			t.Fatalf("update %d not written at once (a settle began):\n%s", i, got)
		}
	}
	toldNothing(t, told)
	if p := r.Problem(); p != nil {
		t.Errorf("problem %v", p)
	}
	if strings.Contains(log.String(), "writing resolv.conf in place") {
		t.Errorf("the node's own write began a settle:\n%s", log.String())
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, source); got != isp {
		t.Errorf("restored through the mount\n%s\nwant\n%s", got, isp)
	}
}
