package lab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// MaxLabsEnv caps how many labs may be starting or running from tests and
// labctl gotest at once, across every checkout of this user on the host.
const MaxLabsEnv = "THINKPOL_LAB_MAX_LABS"

const defaultMaxLabs = 12

// lockDir holds the host-wide locks: one for allocating subnets, one per lab
// slot.
func lockDir() (string, error) {
	dir := filepath.Join(os.TempDir(), "thinkpol-lab-locks")
	return dir, os.MkdirAll(dir, 0o700)
}

// waitLock takes the first free lock among paths, polling until ctx ends.
func waitLock(ctx context.Context, what string, paths ...string) (release func(), err error) {
	for {
		for _, p := range paths {
			f, ok, err := tryLock(p)
			if err != nil {
				return nil, err
			}
			if ok {
				return func() { _ = f.Close() }, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("lab: waiting for %s: %w", what, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// acquireSlot waits for one of the host's lab slots.
func acquireSlot(ctx context.Context) (func(), error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	n := defaultMaxLabs
	if v := os.Getenv(MaxLabsEnv); v != "" {
		if n, err = strconv.Atoi(v); err != nil || n < 1 {
			return nil, fmt.Errorf("lab: %s=%q: want a positive number", MaxLabsEnv, v)
		}
	}
	paths := make([]string, n)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("slot-%d.lock", i))
	}
	return waitLock(ctx, "a free lab slot ("+MaxLabsEnv+")", paths...)
}

// lockAllocation serializes choosing subnets and creating networks, host-wide.
func lockAllocation(ctx context.Context) (func(), error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	return waitLock(ctx, "the subnet allocation lock", filepath.Join(dir, "subnets.lock"))
}
