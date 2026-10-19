//go:build linux && !android

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// cgroupRoot is the cgroup v2 mount; a server's provisioning puts the agent
// on the unified hierarchy.
const cgroupRoot = "/sys/fs/cgroup"

// cgroupParent is the supervisor's own cgroup directory, under which each
// worker gets a leaf cgroup. It is best-effort: where cgroup v2 can't be
// delegated (an old host, a container without it), New reports it and the
// supervisor falls back to the workers' own rlimits.
type cgroupParent struct {
	dir string
}

// newCgroupParent creates the parent cgroup and enables the controllers a
// worker leaf needs (memory, pids).
func newCgroupParent() (*cgroupParent, error) {
	if !isCgroup2(cgroupRoot) {
		return nil, errors.New("not a cgroup v2 unified hierarchy")
	}
	dir := filepath.Join(cgroupRoot, "thinkpol")
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	// Enable the controllers for the parent's children; harmless if already
	// enabled, an error if the host didn't delegate them.
	avail, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	for _, ctrl := range []string{"memory", "pids"} {
		if !strings.Contains(" "+string(avail)+" ", " "+ctrl+" ") {
			return nil, fmt.Errorf("controller %s not delegated to %s", ctrl, dir)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+"+ctrl), 0); err != nil {
			return nil, fmt.Errorf("enable %s under %s: %w", ctrl, dir, err)
		}
	}
	return &cgroupParent{dir: dir}, nil
}

func (p *cgroupParent) remove() error {
	if err := os.Remove(p.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove cgroup %s: %w", p.dir, err)
	}
	return nil
}

// child creates a worker's leaf cgroup with the given caps (0 leaves a limit
// unset) and opens it, so the worker can be clone'd straight into it
// (UseCgroupFD).
func (p *cgroupParent) child(name string, memoryMax, pidsMax int64) (*cgroup, error) {
	dir := filepath.Join(p.dir, name)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if memoryMax > 0 {
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(strconv.FormatInt(memoryMax, 10)), 0); err != nil {
			_ = os.Remove(dir)
			return nil, err
		}
	}
	if pidsMax > 0 {
		if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.FormatInt(pidsMax, 10)), 0); err != nil {
			_ = os.Remove(dir)
			return nil, err
		}
	}
	f, err := os.OpenFile(dir, os.O_RDONLY, 0)
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	return &cgroup{dir: dir, f: f}, nil
}

// cgroup is one worker's leaf cgroup, reused across its restarts.
type cgroup struct {
	dir string
	f   *os.File
}

func (c *cgroup) fd() int { return int(c.f.Fd()) }

func (c *cgroup) remove() error {
	_ = c.f.Close()
	// The cgroup empties when the worker dies; removing it may need a
	// retry while the kernel reaps: retries every 2 ms, about 100 ms in
	// all.
	var err error
	for i := range 50 {
		if i > 0 {
			time.Sleep(2 * time.Millisecond)
		}
		if err = os.Remove(c.dir); err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, unix.EBUSY) {
			break
		}
	}
	return fmt.Errorf("remove cgroup %s: %w", c.dir, err)
}

func isCgroup2(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Type == unix.CGROUP2_SUPER_MAGIC
}

// sealedMemfd writes data to an anonymous memory file sealed against changes,
// for passing a payload too large for one packet over the socket without ever
// touching a disk.
func sealedMemfd(name string, data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("memfd: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return nil, err
	}
	// Rewind, so a reader that reads from the current offset still gets the
	// whole file (the worker reads from offset 0 regardless).
	if _, err := f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seal memfd: %w", err)
	}
	return f, nil
}
