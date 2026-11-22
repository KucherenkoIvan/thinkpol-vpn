package testcache

import (
	"encoding/json"
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
			"stat absent\n" +
			"stat ../../lab/m1.yaml\n" +
			"stat ../../lab/gone/x\n"),
	}
	write(t, filepath.Join(f.src, "internal/pkg/testdata/a.golden"), "golden")
	write(t, filepath.Join(f.src, "lab/maps/m0.yaml"), "map")
	write(t, filepath.Join(f.bin, "thinkpol"), "binary")
	f.resolve = MountResolver(Mount{Node: "/src", Host: f.src, Watch: true}, Mount{Node: "/opt/thinkpol/bin", Host: f.bin})
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

// afterWrites is a run's start after every file written so far, the clock
// slack included: the inputs are older than the run.
func afterWrites() time.Time { return time.Now().Add(clockSlack + time.Millisecond) }

// record stores a pass of a run that started after the fixture's files were
// written.
func (f *fixture) record(t *testing.T) {
	t.Helper()
	if err := f.store.Record(f.action, f.log, f.resolve, afterWrites(), Tally{Passed: 3, Skipped: 1}); err != nil {
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
			write(t, filepath.Join(f.src, "internal/pkg/absent"), "")
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

// Runs that differ only in what they read outside the mounts (a
// t.TempDir's random name) share an input list, so a pass recorded before
// another run's still serves its inputs.
func TestScratchPathsDontSplitTheInputs(t *testing.T) {
	f := newFixture(t)
	golden := filepath.Join(f.src, "internal/pkg/testdata/a.golden")
	f.log = append(f.log, "open /tmp/TestA1/001/x\n"...)
	f.record(t)
	write(t, golden, "golden2")
	f.log = append(f.log, "open /tmp/TestA2/001/x\n"...)
	f.record(t)
	write(t, golden, "golden")
	if !f.hit(t) {
		t.Fatal("the first pass is lost after a run with other scratch paths")
	}
}

// What changed in the checkout after the run started, the run may or may
// not have seen: such a run is not recorded, whatever kind of input
// changed, nor when a directory above an input changed. The lab's binary
// directory is the run's own and not watched. The fixture's missing inputs
// are in lab/ and internal/pkg, so a change in testdata or lab/maps is seen
// through the input itself; the cases about directories above an input
// read only lab/conf/v1/c.yaml, so that only its directories can see them.
func TestInputChangedDuringTheRunIsNotRecorded(t *testing.T) {
	golden := func(f *fixture) string { return filepath.Join(f.src, "internal/pkg/testdata/a.golden") }
	maps := func(f *fixture) string { return filepath.Join(f.src, "lab/maps/m0.yaml") }
	old := time.Now().Add(-24 * time.Hour)
	for _, tc := range []struct {
		name string
		// before runs before the run starts, during after it.
		before, during func(t *testing.T, f *fixture)
		// justBefore: before ran just before the start, within a coarse
		// file clock's error, and during is empty.
		justBefore bool
		recorded   bool
	}{
		{name: "file rewritten just before the start", before: func(t *testing.T, f *fixture) {
			write(t, golden(f), "golden2")
		}, justBefore: true},
		{name: "file rewritten", during: func(t *testing.T, f *fixture) {
			write(t, golden(f), "golden2")
		}},
		{name: "file touched", during: func(t *testing.T, f *fixture) {
			later := time.Now().Add(time.Hour)
			if err := os.Chtimes(golden(f), later, later); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "file added to an opened directory", during: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "internal/pkg/testdata/b.golden"), "b")
		}},
		{name: "input removed", during: func(t *testing.T, f *fixture) {
			if err := os.Remove(maps(f)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing input created and removed", during: func(t *testing.T, f *fixture) {
			absent := filepath.Join(f.src, "lab/m1.yaml")
			write(t, absent, "")
			if err := os.Remove(absent); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing input's directory created and removed", during: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "lab/gone/x"), "")
			if err := os.RemoveAll(filepath.Join(f.src, "lab/gone")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "old file moved over an input", before: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "m0.old"), "map0")
			if err := os.Chtimes(filepath.Join(f.src, "m0.old"), old, old); err != nil {
				t.Fatal(err)
			}
		}, during: func(t *testing.T, f *fixture) {
			if err := os.Rename(filepath.Join(f.src, "m0.old"), maps(f)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "old times copied onto an input", during: func(t *testing.T, f *fixture) {
			write(t, maps(f), "map0")
			if err := os.Chtimes(maps(f), old, old); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink re-pointed at an old file", before: func(t *testing.T, f *fixture) {
			for _, name := range []string{"m0.a", "m0.b"} {
				write(t, filepath.Join(f.src, "lab/maps", name), "map")
				if err := os.Chtimes(filepath.Join(f.src, "lab/maps", name), old, old); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(maps(f)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("m0.a", maps(f)); err != nil {
				t.Fatal(err)
			}
		}, during: func(t *testing.T, f *fixture) {
			if err := os.Remove(maps(f)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("m0.b", maps(f)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory above an input swapped for an old copy", before: func(t *testing.T, f *fixture) {
			confOnly(t, f, old, "conf", "conf.old")
		}, during: func(t *testing.T, f *fixture) {
			if err := os.Rename(filepath.Join(f.src, "lab/conf"), filepath.Join(f.src, "lab/conf.new")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(f.src, "lab/conf.old"), filepath.Join(f.src, "lab/conf")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory symlink above an input re-pointed", before: func(t *testing.T, f *fixture) {
			confOnly(t, f, old, "conf.a", "conf.b")
			if err := os.Symlink("conf.a", filepath.Join(f.src, "lab/conf")); err != nil {
				t.Fatal(err)
			}
		}, during: func(t *testing.T, f *fixture) {
			if err := os.Remove(filepath.Join(f.src, "lab/conf")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("conf.b", filepath.Join(f.src, "lab/conf")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "file added in a directory above an input", before: func(t *testing.T, f *fixture) {
			confOnly(t, f, old, "conf")
		}, during: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "lab/new.txt"), "x")
		}},
		{name: "lab binary rebuilt", during: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.bin, "thinkpol"), "binary2")
		}, recorded: true},
		{name: "file the test never read", before: func(t *testing.T, f *fixture) {
			if err := os.Mkdir(filepath.Join(f.src, "other"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, during: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.src, "other/x.txt"), "x")
		}, recorded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			if tc.before != nil {
				tc.before(t, f)
			}
			started := time.Now()
			if !tc.justBefore {
				started = afterWrites()
				time.Sleep(time.Until(started))
				tc.during(t, f)
			}
			err := f.store.Record(f.action, f.log, f.resolve, started, Tally{Passed: 3, Skipped: 1})
			if tc.recorded {
				if err != nil {
					t.Fatalf("Record: %v", err)
				}
				if !f.hit(t) {
					t.Fatal("miss after recording")
				}
				return
			}
			if !errors.Is(err, ErrInputChanged) {
				t.Fatalf("Record: %v, want ErrInputChanged", err)
			}
			if f.hit(t) {
				t.Fatal("hit for a run whose input changed under it")
			}
		})
	}
}

// confOnly makes the fixture's test read only lab/conf/v1/c.yaml, and
// writes it, with old times, under lab/<dir> for each of dirs.
func confOnly(t *testing.T, f *fixture, old time.Time, dirs ...string) {
	t.Helper()
	f.log = []byte("# test log\nopen ../../lab/conf/v1/c.yaml\n")
	for _, dir := range dirs {
		name := filepath.Join(f.src, "lab", dir, "v1/c.yaml")
		write(t, name, "conf")
		if err := os.Chtimes(name, old, old); err != nil {
			t.Fatal(err)
		}
	}
}

// A pass serves for MaxPassAge from when it was recorded, however often it
// is used in between.
func TestOldPassIsAMiss(t *testing.T) {
	for _, tc := range []struct {
		name string
		age  time.Duration
		hit  bool
	}{
		{"a day old", 24 * time.Hour, true},
		{"just within", MaxPassAge - time.Hour, true},
		{"too old", MaxPassAge + time.Hour, false},
		{"from the future", -time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.record(t)
			if !f.hit(t) { // a hit renews the record's file, not its age
				t.Fatal("miss")
			}
			pass := records(t, f.store)[1]
			b, err := os.ReadFile(pass)
			if err != nil {
				t.Fatal(err)
			}
			var rec map[string]any
			if err := json.Unmarshal(b, &rec); err != nil {
				t.Fatal(err)
			}
			rec["Recorded"] = time.Now().Add(-tc.age)
			if b, err = json.Marshal(rec); err != nil {
				t.Fatal(err)
			}
			write(t, pass, string(b))
			if got := f.hit(t); got != tc.hit {
				t.Fatalf("hit %v, want %v", got, tc.hit)
			}
		})
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
			if err := f.store.Record(f.action, f.log, f.resolve, afterWrites(), Tally{Passed: 3, Skipped: 1}); err != nil {
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
	r := MountResolver(Mount{Node: "/src", Host: "/h/checkout", Watch: true}, Mount{Node: "/opt/thinkpol/bin", Host: "/h/bin"})
	type resolved struct {
		host, root string
	}
	checkout := filepath.FromSlash("/h/checkout")
	for in, want := range map[string]resolved{
		"/src":                       {checkout, checkout},
		"/src/a/b":                   {filepath.FromSlash("/h/checkout/a/b"), checkout},
		"/srcx/a":                    {},
		"/opt/thinkpol/bin/thinkpol": {filepath.FromSlash("/h/bin/thinkpol"), ""},
		"/tmp/x":                     {},
	} {
		if host, root := r(in); host != want.host || root != want.root {
			t.Errorf("%s resolves to %q (watch root %q), want %q (watch root %q)", in, host, root, want.host, want.root)
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
