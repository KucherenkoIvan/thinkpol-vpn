package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/testcache"
)

// GoTestCache, given to GoTestEach, skips a package whose tests passed in a
// node before with every input unchanged, and records the packages that
// pass (lab/testcache has what a key covers).
type GoTestCache struct {
	Store testcache.Store
	// Harness is the hash of the program that sets labs up: a change to
	// how a node is configured changes it.
	Harness string

	mu     sync.Mutex
	engine string // once per process
}

// Records not used for this long go, checked at most once per
// cacheTrimInterval by whichever run comes first.
const (
	cacheMaxAge       = 30 * 24 * time.Hour
	cacheTrimInterval = 24 * time.Hour
)

// NewGoTestCache is a cache in the user's store (testcache.DefaultDir),
// shared by every run on the machine, with the running program as the
// harness. It trims the store's old records first. A cache never fails a
// run: when it can't be set up it is nil (every package runs), and a failed
// trim leaves it in use; either is said on w.
func NewGoTestCache(w io.Writer) *GoTestCache {
	return newGoTestCache(w, testcache.DefaultDir, os.Executable)
}

func newGoTestCache(w io.Writer, storeDir, executable func() (string, error)) *GoTestCache {
	dir, err := storeDir()
	var exe, harness string
	if err == nil {
		exe, err = executable()
	}
	if err == nil {
		harness, err = testcache.HashFile(exe)
	}
	if err != nil {
		_, _ = fmt.Fprintf(w, "lab: results cache off, every package runs: %v\n", err)
		return nil
	}
	c := &GoTestCache{Store: testcache.Store{Dir: dir}, Harness: harness}
	if err := c.Store.Trim(cacheMaxAge, cacheTrimInterval); err != nil {
		_, _ = fmt.Fprintf(w, "lab: results cache: trimming old records: %v\n", err)
	}
	return c
}

// goTestEntry is a package's key in the cache, for one run.
type goTestEntry struct {
	action  testcache.Action
	resolve testcache.Resolver
}

// entry is the key of running the test binary name, in p's binary
// directory, for pkg with env and args, as goTest runs it. The checkout's
// files are read at SrcDir, the run's binaries at BinDir; the seccomp
// profile, which Compose reads on the host, counts as part of the harness.
func (c *GoTestCache) entry(ctx context.Context, root string, p preparedRun, name string, pkg GoPackage, env, args []string) (*goTestEntry, error) {
	binHash, err := testcache.HashFile(filepath.Join(p.bin.path, "tests", name))
	if err != nil {
		return nil, err
	}
	seccomp, err := testcache.HashFile(filepath.Join(root, seccompProfilePath))
	if err != nil {
		return nil, err
	}
	engine, err := c.engineKey(ctx, p.img)
	if err != nil {
		return nil, err
	}
	return &goTestEntry{
		action: testcache.Action{
			ImportPath: pkg.ImportPath,
			TestBinary: binHash,
			Image:      p.img.ref + " " + p.img.platform, // the image's ID (prepare)
			Engine:     engine,
			Harness:    c.Harness + " seccomp " + seccomp,
			Dir:        path.Join(SrcDir, pkg.Dir),
			Args:       args,
			Env:        env,
		},
		resolve: testcache.MountResolver(
			testcache.Mount{Node: SrcDir, Host: root, Watch: true},
			testcache.Mount{Node: BinDir, Host: p.bin.path},
		),
	}, nil
}

// freshRun is how a package's run in a fresh lab went.
type freshRun struct {
	labErr, testErr error
	testLog         []byte // its -test.testlogfile, when asked for
	logErr          error  // reading testLog back
}

// record stores run as a pass of entry, if it is one. A run whose tests
// failed or whose lab failed is never recorded (nil: nothing to record),
// nor one whose test log couldn't be read back (an error).
func (c *GoTestCache) record(entry *goTestEntry, run freshRun, started time.Time, t TestTally) error {
	if run.labErr != nil || run.testErr != nil {
		return nil
	}
	if run.logErr != nil {
		return run.logErr
	}
	return c.Store.Record(entry.action, run.testLog, entry.resolve, started, testcache.Tally{Passed: t.Passed, Skipped: t.Skipped})
}

// engineInfo is what of the Docker engine decides how a node's tests run:
// its version, its kernel (which the nodes share) and the CPUs they get.
type engineInfo struct {
	ServerVersion, KernelVersion, OperatingSystem, Architecture string
	NCPU                                                        int
	Name                                                        string // the engine host's name
}

// key is the engine's part of an action. bridgeNetfilter is part of it
// because tests skip without br_netfilter, which a reboot or a modprobe
// changes under the same kernel, as the CPU count changes in Docker
// Desktop's settings.
func (e engineInfo) key(bridgeNetfilter bool) string {
	return fmt.Sprintf("%s %s %s %s cpus=%d bridge-netfilter=%t",
		e.ServerVersion, e.KernelVersion, e.OperatingSystem, e.Architecture, e.NCPU, bridgeNetfilter)
}

// engineKey returns the Docker engine's key, asking Docker once per process.
func (c *GoTestCache) engineKey(ctx context.Context, img image) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine != "" {
		return c.engine, nil
	}
	res, err := docker(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return "", err
	}
	var info engineInfo
	if err := json.Unmarshal([]byte(res.Stdout), &info); err != nil {
		return "", fmt.Errorf("lab: docker info: %w", err)
	}
	bridge, err := bridgeNetfilter(ctx, info, img)
	if err != nil {
		return "", err
	}
	c.engine = info.key(bridge)
	return c.engine, nil
}

// bridgeNetfilter says whether the engine's kernel has br_netfilter, as a
// node sees it (/proc/sys/net/bridge): looked up on this host when the
// engine runs on it, else in a container of the lab image (Docker
// Desktop's VM), which is one container start per process.
func bridgeNetfilter(ctx context.Context, info engineInfo, img image) (bool, error) {
	if host, err := os.Hostname(); err == nil && runtime.GOOS == "linux" && host == info.Name {
		_, err := os.Stat("/proc/sys/net/bridge")
		return err == nil, nil
	}
	res, err := docker(ctx, "run", "--rm", "--network", "none", "--platform", img.platform, "--entrypoint", "test", img.ref, "-d", "/proc/sys/net/bridge")
	switch {
	case err == nil:
		return true, nil
	case res.ExitCode == 1:
		return false, nil
	}
	return false, fmt.Errorf("lab: looking for br_netfilter: %w", err)
}
