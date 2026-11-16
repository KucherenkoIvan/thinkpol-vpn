package lab

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
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
	engine string            // once per process
	images map[string]string // image ref → ID
}

// Records not used for this long go, checked at most once per
// cacheTrimInterval by whichever run comes first.
const (
	cacheMaxAge       = 30 * 24 * time.Hour
	cacheTrimInterval = 24 * time.Hour
)

// NewGoTestCache is a cache in the user's store (testcache.DefaultDir),
// shared by every run on the machine, with the running program as the
// harness. It trims the store's old records first.
func NewGoTestCache() (*GoTestCache, error) {
	dir, err := testcache.DefaultDir()
	if err != nil {
		return nil, fmt.Errorf("lab: results cache: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("lab: results cache: %w", err)
	}
	harness, err := testcache.HashFile(exe)
	if err != nil {
		return nil, fmt.Errorf("lab: results cache: %w", err)
	}
	c := &GoTestCache{Store: testcache.Store{Dir: dir}, Harness: harness}
	if err := c.Store.Trim(cacheMaxAge, cacheTrimInterval); err != nil {
		return nil, fmt.Errorf("lab: results cache: %w", err)
	}
	return c, nil
}

// goTestEntry is a package's key in the cache, for one run.
type goTestEntry struct {
	action  testcache.Action
	resolve testcache.Resolver
	logErr  error // reading the run's test log back
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
	engine, imageID, err := c.lab(ctx, p.img)
	if err != nil {
		return nil, err
	}
	return &goTestEntry{
		action: testcache.Action{
			ImportPath: pkg.ImportPath,
			TestBinary: binHash,
			Image:      imageID,
			Engine:     engine,
			Harness:    c.Harness + " seccomp " + seccomp,
			Dir:        path.Join(SrcDir, pkg.Dir),
			Args:       args,
			Env:        env,
		},
		resolve: testcache.MountResolver(map[string]string{SrcDir: root, BinDir: p.bin.path}),
	}, nil
}

// lab returns the Docker engine (its version and its kernel's, which the
// nodes share) and the image's ID, asking Docker once per process.
func (c *GoTestCache) lab(ctx context.Context, img image) (engine, imageID string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine == "" {
		res, err := docker(ctx, "info", "--format", "{{.ServerVersion}} {{.KernelVersion}} {{.OperatingSystem}} {{.Architecture}}")
		if err != nil {
			return "", "", err
		}
		c.engine = strings.TrimSpace(res.Stdout)
	}
	id, ok := c.images[img.ref]
	if !ok {
		res, err := docker(ctx, "image", "inspect", "--format", "{{.Id}}", img.ref)
		if err != nil {
			return "", "", err
		}
		id = strings.TrimSpace(res.Stdout) + " " + img.platform
		if c.images == nil {
			c.images = map[string]string{}
		}
		c.images[img.ref] = id
	}
	return c.engine, id, nil
}
