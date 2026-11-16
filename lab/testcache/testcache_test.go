package testcache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture is a checkout with a package that reads testdata, a file of
// another package's and a lab binary, and the log its test binary wrote.
type fixture struct {
	store   Store
	src     string // mounted at /src
	bin     string // mounted at /opt/thinkpol/bin
	action  Action
	log     []byte
	resolve Resolver
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{
		store: Store{Dir: filepath.Join(dir, "cache")},
		src:   filepath.Join(dir, "checkout"),
		bin:   filepath.Join(dir, "bin"),
		action: Action{
			ImportPath: "example.net/x/internal/pkg",
			TestBinary: "b1",
			Image:      "sha256:i1 linux/amd64",
			Engine:     "29.0.0 6.8.0 Debian amd64",
			Harness:    "h1 seccomp s1",
			Dir:        "/src/internal/pkg",
			Args:       []string{"-test.v", "-test.run", "X"},
			Env:        []string{"THINKPOL_LAB_PERF=1"},
		},
		log: []byte("# test log\n" +
			"getenv THINKPOL_LAB\n" +
			"open testdata/a.golden\n" +
			"stat ../../lab/maps/m0.yaml\n" +
			"open testdata\n" +
			"stat /opt/thinkpol/bin/thinkpol\n" +
			"open /etc/os-release\n" +
			"stat testdata/absent\n"),
	}
	write(t, filepath.Join(f.src, "internal/pkg/testdata/a.golden"), "golden")
	write(t, filepath.Join(f.src, "lab/maps/m0.yaml"), "map")
	write(t, filepath.Join(f.bin, "thinkpol"), "binary")
	f.resolve = MountResolver(map[string]string{"/src": f.src, "/opt/thinkpol/bin": f.bin})
	return f
}

func write(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// record stores a pass that started a second ago.
func (f *fixture) record(t *testing.T) {
	t.Helper()
	if err := f.store.Record(f.action, f.log, f.resolve, time.Now().Add(time.Second), Tally{Passed: 3, Skipped: 1}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) hit(t *testing.T) bool {
	t.Helper()
	tally, ok := f.store.Lookup(f.action, f.resolve)
	if ok && tally != (Tally{Passed: 3, Skipped: 1}) {
		t.Fatalf("cached tally %+v, want the recorded one", tally)
	}
	return ok
}

func TestRecordedPassIsAHit(t *testing.T) {
	f := newFixture(t)
	if f.hit(t) {
		t.Fatal("hit before anything was recorded")
	}
	f.record(t)
	if !f.hit(t) {
		t.Fatal("miss after recording a pass with nothing changed")
	}
}

// Every part of the action is in the key: a recorded pass of the action as
// it was doesn't serve it changed.
func TestActionChangeIsAMiss(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Action)
	}{
		{"import path", func(a *Action) { a.ImportPath += "2" }},
		{"test binary", func(a *Action) { a.TestBinary = "b2" }},
		{"image", func(a *Action) { a.Image = "sha256:i2 linux/amd64" }},
		{"engine", func(a *Action) { a.Engine = "29.0.0 6.9.0 Debian amd64" }},
		{"harness", func(a *Action) { a.Harness = "h2 seccomp s1" }},
		{"working directory", func(a *Action) { a.Dir = "/src/internal/other" }},
		{"args", func(a *Action) { a.Args = []string{"-test.v", "-test.run", "Y"} }},
		{"args order", func(a *Action) { a.Args = []string{"-test.run", "X", "-test.v"} }},
		{"env", func(a *Action) { a.Env = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.record(t)
			tc.change(&f.action)
			if f.hit(t) {
				t.Fatalf("hit after the action's %s changed", tc.name)
			}
		})
	}
}

// Every file the test opened or stat'ed under a mount is an input, by
// content; the image's own files are not.
func TestInputChangeIsAMiss(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *fixture)
		hit    bool
	}{
		{"testdata content", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "internal/pkg/testdata/a.golden"), "golden2")
		}, false},
		{"another package's file", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "lab/maps/m0.yaml"), "map2")
		}, false},
		{"lab binary", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.bin, "thinkpol"), "binary2")
		}, false},
		{"file added to an opened directory", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "internal/pkg/testdata/b.golden"), "b")
		}, false},
		{"input removed", func(t *testing.T, f *fixture) {
			if err := os.Remove(filepath.Join(f.src, "lab/maps/m0.yaml")); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"missing input appears", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "internal/pkg/testdata/absent"), "")
		}, false},
		{"input rewritten with the same content", func(t *testing.T, f *fixture) {
			name := filepath.Join(f.src, "internal/pkg/testdata/a.golden")
			write(t, name, "golden")
			later := time.Now().Add(time.Hour)
			if err := os.Chtimes(name, later, later); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"file the test never read", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "internal/pkg/other.txt"), "x")
		}, true},
		{"same path outside the mounts", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "etc/os-release"), "x")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.record(t)
			tc.change(t, f)
			if got := f.hit(t); got != tc.hit {
				t.Fatalf("hit %v, want %v", got, tc.hit)
			}
		})
	}
}

// Two checkouts whose inputs differ keep a pass each.
func TestPassPerInputs(t *testing.T) {
	f := newFixture(t)
	f.record(t)
	other := newFixture(t)
	other.store, other.action = f.store, f.action
	write(t, filepath.Join(other.src, "internal/pkg/testdata/a.golden"), "golden2")
	if other.hit(t) {
		t.Fatal("hit for other inputs")
	}
	other.record(t)
	if !f.hit(t) || !other.hit(t) {
		t.Fatal("a checkout's pass was lost to the other's")
	}
}

func TestInputChangedDuringTheRunIsNotRecorded(t *testing.T) {
	f := newFixture(t)
	started := time.Now()
	later := started.Add(time.Second)
	if err := os.Chtimes(filepath.Join(f.src, "internal/pkg/testdata/a.golden"), later, later); err != nil {
		t.Fatal(err)
	}
	err := f.store.Record(f.action, f.log, f.resolve, started, Tally{Passed: 3, Skipped: 1})
	if !errors.Is(err, ErrInputChanged) {
		t.Fatalf("Record: %v, want ErrInputChanged", err)
	}
	if f.hit(t) {
		t.Fatal("hit for a run whose input changed under it")
	}
}

func TestLogWithoutHeaderIsNotRecorded(t *testing.T) {
	f := newFixture(t)
	f.log = f.log[len("# test log\n"):]
	if err := f.store.Record(f.action, f.log, f.resolve, time.Now(), Tally{}); err == nil {
		t.Fatal("recorded a pass from a log without its header")
	}
	if f.hit(t) {
		t.Fatal("hit")
	}
}

func TestBrokenRecordIsAMiss(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(t *testing.T, f *fixture, files []string)
	}{
		{"garbage", func(t *testing.T, f *fixture, files []string) {
			for _, p := range files {
				write(t, p, "\x00{not json")
			}
		}},
		{"truncated", func(t *testing.T, f *fixture, files []string) {
			for _, p := range files {
				b, _ := os.ReadFile(p)
				write(t, p, string(b[:len(b)/2]))
			}
		}},
		{"another key's record", func(t *testing.T, f *fixture, files []string) {
			b, _ := os.ReadFile(files[0])
			write(t, files[1], string(b))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.record(t)
			files := records(t, f.store)
			if len(files) != 2 {
				t.Fatalf("records %v, want an action and a pass", files)
			}
			tc.breakIt(t, f, files)
			if f.hit(t) {
				t.Fatal("hit from a broken record")
			}
			f.record(t)
			if !f.hit(t) {
				t.Fatal("a new pass doesn't replace a broken record")
			}
		})
	}
}

// records lists the store's record files, the pass ("-p") last.
func records(t *testing.T, s Store) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(s.Dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() != trimMarker {
			out = append(out, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(out, func(a, b string) int { return strings.Compare(a[len(a)-2:], b[len(b)-2:]) })
	return out
}

// Runs sharing the store write and read the same keys at once: a reader
// sees a whole record or none, and no temporary file is left.
func TestConcurrentRunsShareTheStore(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 32 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := f.store.Record(f.action, f.log, f.resolve, time.Now().Add(time.Second), Tally{Passed: 3, Skipped: 1}); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if tally, ok := f.store.Lookup(f.action, f.resolve); ok && tally != (Tally{Passed: 3, Skipped: 1}) {
				errs <- fmt.Errorf("reader %d: tally %+v", i, tally)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if !f.hit(t) {
		t.Fatal("miss after the writers")
	}
	if files := records(t, f.store); len(files) != 2 {
		t.Fatalf("store holds %v, want one action and one pass record", files)
	}
}

func TestParseTestLog(t *testing.T) {
	log := "# test log\n" +
		"getenv HOME\n" +
		"open testdata/x\n" +
		"stat ./testdata/x\n" +
		"open /etc/hosts\n" +
		"chdir /src/other\n" +
		"open y\n" +
		"stat ../z\n" +
		"garbage\n"
	got, err := ParseTestLog([]byte(log), "/src/pkg")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/etc/hosts", "/src/other", "/src/other/y", "/src/pkg/testdata/x", "/src/z"}
	if !slices.Equal(got, want) {
		t.Fatalf("inputs %q, want %q", got, want)
	}
	if _, err := ParseTestLog([]byte("open x\n"), "/src"); err == nil {
		t.Fatal("parsed a log without its header")
	}
}

func TestMountResolver(t *testing.T) {
	r := MountResolver(map[string]string{"/src": "/h/checkout", "/opt/thinkpol/bin": "/h/bin"})
	for in, want := range map[string]string{
		"/src":                       filepath.FromSlash("/h/checkout"),
		"/src/a/b":                   filepath.FromSlash("/h/checkout/a/b"),
		"/srcx/a":                    "",
		"/opt/thinkpol/bin/thinkpol": filepath.FromSlash("/h/bin/thinkpol"),
		"/tmp/x":                     "",
	} {
		if got := r(in); got != want {
			t.Errorf("%s resolves to %q, want %q", in, got, want)
		}
	}
}

func TestTrim(t *testing.T) {
	f := newFixture(t)
	f.record(t)
	stale := newFixture(t)
	stale.store = f.store
	stale.action.ImportPath = "example.net/x/stale"
	stale.record(t)
	old := time.Now().Add(-48 * time.Hour)
	// Age every record, then use the fresh run's.
	for _, p := range records(t, f.store) {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if !f.hit(t) { // a hit renews its records
		t.Fatal("miss")
	}
	if err := f.store.Trim(24*time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !f.hit(t) {
		t.Fatal("trim removed records in use")
	}
	if stale.hit(t) {
		t.Fatal("trim kept stale records")
	}
	// Within the interval a second trim does nothing.
	stale.record(t)
	for _, p := range records(t, f.store) {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.Trim(24*time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !stale.hit(t) {
		t.Fatal("a second trim within the interval removed records")
	}
}
