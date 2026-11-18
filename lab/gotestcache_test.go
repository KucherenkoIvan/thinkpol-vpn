package lab

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/testcache"
)

// cacheFixture is a checkout, a run's binary directory with a package's
// test binary, and a cache whose engine is already known (no Docker).
type cacheFixture struct {
	cache     *GoTestCache
	root, bin string
	p         preparedRun
	pkg       GoPackage
	env, args []string
}

// cacheFixtureLog is what the package's test binary read: its testdata and
// the lab's thinkpol binary.
var cacheFixtureLog = []byte("# test log\nopen testdata/a\nstat /opt/thinkpol/bin/thinkpol\n")

func newCacheFixture(t *testing.T) *cacheFixture {
	t.Helper()
	f := &cacheFixture{
		cache: &GoTestCache{Store: testcache.Store{Dir: t.TempDir()}, Harness: "h1", engine: "e1"},
		root:  t.TempDir(),
		bin:   t.TempDir(),
		pkg:   GoPackage{ImportPath: "example.net/x/internal/pkg", Dir: "internal/pkg"},
		env:   []string{"X=1"},
		args:  []string{"-test.v"},
	}
	f.p = preparedRun{img: image{ref: "sha256:i1", platform: "linux/amd64"}, bin: &runBinaries{path: f.bin}}
	writeFileT(t, filepath.Join(f.root, seccompProfilePath), "seccomp1")
	writeFileT(t, filepath.Join(f.root, "internal/pkg/testdata/a"), "a1")
	writeFileT(t, filepath.Join(f.bin, "tests/pkg.test"), "test binary 1")
	writeFileT(t, filepath.Join(f.bin, "thinkpol"), "thinkpol 1")
	return f
}

func writeFileT(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *cacheFixture) entry(t *testing.T) *goTestEntry {
	t.Helper()
	e, err := f.cache.entry(t.Context(), f.root, f.p, "pkg.test", f.pkg, f.env, f.args)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// record records run as goTestPackage does, for a run that started after
// every file was written: the checkout is watched for changes since then.
func (f *cacheFixture) record(t *testing.T, run freshRun) error {
	t.Helper()
	return f.cache.record(f.entry(t), run, time.Now().Add(time.Minute), TestTally{Passed: 2})
}

func (f *cacheFixture) hit(t *testing.T) bool {
	t.Helper()
	e := f.entry(t)
	_, ok := f.cache.Store.Lookup(e.action, e.resolve)
	return ok
}

// Only a pass is recorded: a run whose tests failed, whose lab failed, or
// whose test log didn't come back whole leaves the next run a miss.
func TestOnlyAPassIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		run      freshRun
		recorded bool
	}{
		{"pass", freshRun{testLog: cacheFixtureLog}, true},
		{"tests failed", freshRun{testErr: errors.New("exit status 1"), testLog: cacheFixtureLog}, false},
		{"lab failed", freshRun{labErr: errors.New("compose down: exit 1"), testLog: cacheFixtureLog}, false},
		{"log not read back", freshRun{logErr: errors.New("docker exec: exit 1"), testLog: cacheFixtureLog}, false},
		{"log cut short", freshRun{testLog: cacheFixtureLog[len("# test log\n"):]}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCacheFixture(t)
			err := f.record(t, tc.run)
			if tc.recorded && err != nil {
				t.Fatalf("record: %v", err)
			}
			if got := f.hit(t); got != tc.recorded {
				t.Fatalf("hit %v after the run, want %v", got, tc.recorded)
			}
		})
	}
}

// Every part of how goTestPackage runs a package is in its key: a pass
// recorded before any of them changed doesn't serve the run after.
func TestEntryKeyCoversTheRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *cacheFixture)
		hit    bool
	}{
		{"nothing", func(*testing.T, *cacheFixture) {}, true},
		{"test binary", func(t *testing.T, f *cacheFixture) {
			writeFileT(t, filepath.Join(f.bin, "tests/pkg.test"), "test binary 2")
		}, false},
		{"seccomp profile", func(t *testing.T, f *cacheFixture) {
			writeFileT(t, filepath.Join(f.root, seccompProfilePath), "seccomp2")
		}, false},
		{"image", func(_ *testing.T, f *cacheFixture) { f.p.img.ref = "sha256:i2" }, false},
		{"platform", func(_ *testing.T, f *cacheFixture) { f.p.img.platform = "linux/arm64" }, false},
		{"engine", func(_ *testing.T, f *cacheFixture) { f.cache.engine = "e2" }, false},
		{"harness", func(_ *testing.T, f *cacheFixture) { f.cache.Harness = "h2" }, false},
		{"env", func(_ *testing.T, f *cacheFixture) { f.env = []string{"X=2"} }, false},
		{"args", func(_ *testing.T, f *cacheFixture) { f.args = []string{"-test.v", "-test.run", "Y"} }, false},
		{"testdata", func(t *testing.T, f *cacheFixture) {
			writeFileT(t, filepath.Join(f.root, "internal/pkg/testdata/a"), "a2")
		}, false},
		{"lab binary", func(t *testing.T, f *cacheFixture) {
			writeFileT(t, filepath.Join(f.bin, "thinkpol"), "thinkpol 2")
		}, false},
		{"another run's binary directory, same binaries", func(t *testing.T, f *cacheFixture) {
			f.bin = t.TempDir()
			f.p.bin = &runBinaries{path: f.bin}
			writeFileT(t, filepath.Join(f.bin, "tests/pkg.test"), "test binary 1")
			writeFileT(t, filepath.Join(f.bin, "thinkpol"), "thinkpol 1")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCacheFixture(t)
			if err := f.record(t, freshRun{testLog: cacheFixtureLog}); err != nil {
				t.Fatal(err)
			}
			tc.change(t, f)
			if got := f.hit(t); got != tc.hit {
				t.Fatalf("hit %v after the %s changed, want %v", got, tc.name, tc.hit)
			}
		})
	}
}

// What decides whether a test skips without the code changing is in the
// engine's key.
func TestEngineKeyCoversSkipConditions(t *testing.T) {
	info := engineInfo{ServerVersion: "29.0.0", KernelVersion: "6.8.0", OperatingSystem: "Debian", Architecture: "x86_64", NCPU: 4}
	one := info
	one.NCPU = 1
	for name, other := range map[string]string{
		"one CPU":              one.key(true),
		"without br_netfilter": info.key(false),
	} {
		if other == info.key(true) {
			t.Errorf("%s: same engine key %q", name, other)
		}
	}
}

// A cache that can't be set up never fails the run: it is off, or, when
// only the trim failed, still in use; either is said.
func TestCacheSetupNeverFailsARun(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "labctl")
	writeFileT(t, exe, "labctl")
	notAFile := filepath.Join(t.TempDir(), "store")
	writeFileT(t, notAFile, "")
	ok := func(s string) func() (string, error) { return func() (string, error) { return s, nil } }
	fail := func() (string, error) { return "", errors.New("$HOME is not defined") }
	for _, tc := range []struct {
		name            string
		dir, executable func() (string, error)
		on              bool
		said            string
	}{
		{"set up", ok(t.TempDir()), ok(exe), true, ""},
		{"no cache directory", fail, ok(exe), false, "results cache off"},
		{"no executable", ok(t.TempDir()), fail, false, "results cache off"},
		{"executable unreadable", ok(t.TempDir()), ok(filepath.Join(t.TempDir(), "gone")), false, "results cache off"},
		{"store unwritable", ok(notAFile), ok(exe), true, "trimming old records"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			c := newGoTestCache(&out, tc.dir, tc.executable)
			if (c != nil) != tc.on {
				t.Fatalf("cache %v, want on %v; said %q", c, tc.on, out.String())
			}
			if tc.said == "" && out.Len() > 0 || !strings.Contains(out.String(), tc.said) {
				t.Fatalf("said %q, want %q", out.String(), tc.said)
			}
		})
	}
}

// exitZeroEnv makes TestExitZeroFailsTheRun, run again as a child, call
// os.Exit(0) the way a broken test or the code under it can.
const exitZeroEnv = "THINKPOL_TEST_EXIT_ZERO"

// A test binary run as goTest runs it fails when a test calls os.Exit(0),
// as under go test; otherwise it exits 0 with the rest of its tests unrun,
// a pass the results cache would record.
func TestExitZeroFailsTheRun(t *testing.T) {
	if os.Getenv(exitZeroEnv) != "" {
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], testBinaryArgs([]string{"-test.run=^TestExitZeroFailsTheRun$"})...)
	cmd.Env = append(os.Environ(), exitZeroEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a test calling os.Exit(0) exits 0:\n%s", out)
	}
	if !strings.Contains(string(out), "os.Exit(0)") {
		t.Fatalf("the run failed, but not on os.Exit(0): %v\n%s", err, out)
	}
}
