package agent

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
)

func TestTheWatcherDeliversChangedMaps(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, MapFileName)
	writeFile(t, path, []byte("version 1"), 0o644)
	_, fi, err := readMap(path)
	if err != nil {
		t.Fatal(err)
	}
	reload := make(chan os.Signal, 1)
	logs := logring.New(1 << 16)
	w := &mapWatcher{path: path, interval: 10 * time.Millisecond, reload: reload, log: slog.New(slog.NewTextHandler(logs, nil)), last: fi}
	out := make(chan []byte, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, out) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	select {
	case b := <-out:
		t.Fatalf("delivered %q though nothing changed", b)
	case <-time.After(100 * time.Millisecond):
	}

	// Replaced the way `dev map build` writes it: a new file renamed over.
	tmp := filepath.Join(dir, "map.tmp")
	writeFile(t, tmp, []byte("version 2"), 0o644)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	expect(t, out, "version 2")

	// Missing for a while, then back.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	// Back whole: written in place, a poll could read it still empty.
	replace := func(data []byte, perm os.FileMode) {
		t.Helper()
		writeFile(t, tmp, data, perm)
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	replace([]byte("version 3!"), 0o644)
	expect(t, out, "version 3!")

	// A refused file (others may write it) is said once, not on every
	// poll; modes aren't checked on Windows.
	if runtime.GOOS != "windows" {
		replace([]byte("refused"), 0o666)
		warnings := func() int { return strings.Count(logs.String(), "reading the map file") }
		for deadline := time.Now().Add(5 * time.Second); warnings() == 0 && time.Now().Before(deadline); {
			time.Sleep(w.interval)
		}
		time.Sleep(10 * w.interval) // polls that must say nothing more
		if c := warnings(); c != 1 {
			t.Fatalf("%d warnings:\n%s", c, logs.String())
		}
	}
	replace([]byte("version 4!"), 0o644)
	expect(t, out, "version 4!")

	// SIGHUP reads it even unchanged.
	reload <- os.Interrupt
	expect(t, out, "version 4!")
}

func expect(t *testing.T, out <-chan []byte, want string) {
	t.Helper()
	select {
	case b := <-out:
		if !bytes.Equal(b, []byte(want)) {
			t.Fatalf("delivered %q, want %q", b, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%q not delivered", want)
	}
}
