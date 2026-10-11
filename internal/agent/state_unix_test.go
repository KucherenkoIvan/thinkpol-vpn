//go:build unix

package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// What LoadState refuses that only Unix can express: symlinks, FIFOs,
// foreign owners, a map somewhere others can write.
func TestLoadStateRefusesUntrustedFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		root   bool // needs root to chown
		mutate func(t *testing.T, s *testSpace, dir string) (mapPath string)
		want   string
	}{
		{"a symlinked state directory", false, func(t *testing.T, s *testSpace, dir string) string {
			link := dir + "-link"
			symlink(t, dir, link)
			return link
		}, "a symlink is refused"},
		{"a symlinked key file", false, func(t *testing.T, s *testSpace, dir string) string {
			moveAndLink(t, filepath.Join(dir, NodeKeyFile))
			return ""
		}, "a symlink is refused"},
		{"a symlinked trust file", false, func(t *testing.T, s *testSpace, dir string) string {
			moveAndLink(t, filepath.Join(dir, TrustFile))
			return ""
		}, "a symlink is refused"},
		{"a symlinked map", false, func(t *testing.T, s *testSpace, dir string) string {
			moveAndLink(t, filepath.Join(dir, MapFileName))
			return ""
		}, "a symlink is refused"},
		{"a FIFO for a key file", false, func(t *testing.T, s *testSpace, dir string) string {
			fifo(t, filepath.Join(dir, NodeKeyFile))
			return ""
		}, "not a regular file"},
		{"a FIFO for the map", false, func(t *testing.T, s *testSpace, dir string) string {
			fifo(t, filepath.Join(dir, MapFileName))
			return ""
		}, "not a regular file"},
		{"a map others can write", false, func(t *testing.T, s *testSpace, dir string) string {
			chmod(t, filepath.Join(dir, MapFileName), 0o664)
			return ""
		}, "chmod go-w"},
		{"a map in a directory others can write", false, func(t *testing.T, s *testSpace, dir string) string {
			other := filepath.Join(t.TempDir(), "maps")
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(other, "m.bin"), s.build(t, 1), 0o644)
			chmod(t, other, 0o777)
			return filepath.Join(other, "m.bin")
		}, "chmod go-w"},
		{"a state directory of another user", true, func(t *testing.T, s *testSpace, dir string) string {
			chown(t, dir)
			return ""
		}, "owned by uid 4321"},
		{"a key file of another user", true, func(t *testing.T, s *testSpace, dir string) string {
			chown(t, filepath.Join(dir, NodeKeyFile))
			return ""
		}, "owned by uid 4321"},
		{"a trust file of another user", true, func(t *testing.T, s *testSpace, dir string) string {
			chown(t, filepath.Join(dir, TrustFile))
			return ""
		}, "owned by uid 4321"},
		{"a map of another user", true, func(t *testing.T, s *testSpace, dir string) string {
			chown(t, filepath.Join(dir, MapFileName))
			return ""
		}, "owned by uid 4321"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.root && os.Geteuid() != 0 {
				t.Skip("needs root to give a file away (runs in the lab)")
			}
			s := newTestSpace(t)
			dir := s.stateDir(t, s.b, 1)
			stateDir, mapPath := dir, filepath.Join(dir, MapFileName)
			if p := tc.mutate(t, s, dir); p != "" {
				if strings.HasSuffix(p, "-link") {
					stateDir, mapPath = p, filepath.Join(p, MapFileName)
				} else {
					mapPath = p
				}
			}
			done := make(chan error, 1)
			go func() { _, err := LoadState(stateDir, mapPath); done <- err }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want an error with %q", err, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("LoadState hangs")
			}
		})
	}
}

func TestLoadStateTakesAMapFromElsewhere(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	other := filepath.Join(t.TempDir(), "maps")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(other, "m.bin"), s.build(t, 2), 0o644)
	st, err := LoadState(dir, filepath.Join(other, "m.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Map.Header().Version != 2 || !st.OwnMapUnused {
		t.Fatalf("version %d, own map unused %v", st.Map.Header().Version, st.OwnMapUnused)
	}
}

// A FIFO put where the map was never blocks the watcher, so it never
// blocks shutdown either.
func TestTheWatcherNeverBlocksOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, MapFileName)
	fifo(t, path)
	reload := make(chan os.Signal, 1)
	w := &mapWatcher{path: path, interval: 10 * time.Millisecond, reload: reload, log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	out := make(chan []byte, 1)
	go func() { done <- w.run(ctx, out) }()
	reload <- syscall.SIGHUP
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher blocks on a FIFO")
	}
	select {
	case b := <-out:
		t.Fatalf("delivered %q from a FIFO", b)
	default:
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// moveAndLink moves path aside and puts a symlink to it in its place.
func moveAndLink(t *testing.T, path string) {
	t.Helper()
	aside := path + ".real"
	if err := os.Rename(path, aside); err != nil {
		t.Fatal(err)
	}
	symlink(t, aside, path)
}

func fifo(t *testing.T, path string) {
	t.Helper()
	_ = os.Remove(path)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func chown(t *testing.T, path string) {
	t.Helper()
	if err := os.Chown(path, 4321, 4321); err != nil {
		t.Fatal(err)
	}
}
