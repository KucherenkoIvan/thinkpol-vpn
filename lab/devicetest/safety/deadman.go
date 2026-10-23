//go:build darwin || linux

package safety

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// The dead-man's files in a run's directory.
const (
	// stopFile disarms the dead-man: the restore is done.
	stopFile = "deadman.stop"
	// armedFile says the dead-man watches: "<pid> <start>".
	armedFile = "deadman.armed"
	// heartbeatFile changes each time a restore makes progress, never on
	// a timer: a hung restore lets it go stale.
	heartbeatFile = "restore.heartbeat"
)

// beat says the restore made progress.
func (h *Host) beat() {
	if h.RunDir == nil {
		return
	}
	h.beats++
	_ = trusteddir.WriteFile(h.RunDir, heartbeatFile, fmt.Appendf(nil, "%d %d\n", os.Getpid(), h.beats))
}

// DeadmanConfig is when the dead-man restores.
type DeadmanConfig struct {
	// HelperPID is the helper it watches.
	HelperPID int
	// Deadline is the plan's budget: past it, the dead-man restores
	// unless a restore is making progress.
	Deadline time.Duration
	// Cap is when it restores whatever the heartbeat says (default:
	// Deadline + 10 min).
	Cap time.Duration
	// Stale is how long a heartbeat counts as fresh (default 60 s).
	Stale time.Duration
	// Poll is how often it looks (default 500 ms).
	Poll time.Duration
}

func (c DeadmanConfig) withDefaults() DeadmanConfig {
	if c.Cap == 0 {
		c.Cap = c.Deadline + 10*time.Minute
	}
	if c.Stale == 0 {
		c.Stale = time.Minute
	}
	if c.Poll == 0 {
		c.Poll = 500 * time.Millisecond
	}
	return c
}

// Watch watches a run until its stop file appears (false) or the run must
// be restored (true, and why): the helper is gone without the stop file,
// the deadline has passed with no fresh heartbeat, or the cap has passed.
// Time is Go's monotonic clock, so setting the wall clock moves nothing,
// and the heartbeat is judged by when its content last changed, not by
// its file's time.
func Watch(ctx context.Context, runDir *os.File, cfg DeadmanConfig) (bool, string) {
	cfg = cfg.withDefaults()
	start := time.Now()
	var beat string
	var lastBeat time.Time
	tick := time.NewTicker(cfg.Poll)
	defer tick.Stop()
	for {
		if exists(runDir, stopFile) {
			return false, ""
		}
		if b, err := trusteddir.ReadFile(runDir, heartbeatFile); err == nil && string(b) != beat {
			beat, lastBeat = string(b), time.Now()
		}
		why := ""
		switch elapsed := time.Since(start); {
		case !alive(cfg.HelperPID):
			why = "the helper is gone"
		case elapsed >= cfg.Cap:
			why = fmt.Sprintf("the cap (%v) has passed", cfg.Cap)
		case elapsed >= cfg.Deadline && (lastBeat.IsZero() || time.Since(lastBeat) > cfg.Stale):
			why = fmt.Sprintf("the deadline (%v) has passed with no restore making progress", cfg.Deadline)
		}
		// The stop file once more: a restore writes it before its helper
		// exits.
		if why != "" && !exists(runDir, stopFile) {
			return true, why
		}
		select {
		case <-ctx.Done():
			return false, ""
		case <-tick.C:
		}
	}
}

func exists(dir *os.File, name string) bool {
	_, err := trusteddir.ReadFile(dir, name)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

// Deadman is the dead-man process of a run: it says it is armed, watches,
// and restores the run from its journal when it must, the helper killed
// first.
func Deadman(ctx context.Context, cfg StateConfig, run string, dm DeadmanConfig) error {
	runDir, err := cfg.openRun(run)
	if err != nil {
		return err
	}
	defer func() { _ = runDir.Close() }()
	start, _ := startTime(os.Getpid())
	if err := trusteddir.WriteFile(runDir, armedFile, fmt.Appendf(nil, "%d %d\n", os.Getpid(), start)); err != nil {
		return err
	}
	fire, why := Watch(ctx, runDir, dm)
	if !fire {
		return nil
	}
	if alive(dm.HelperPID) {
		_ = syscall.Kill(dm.HelperPID, syscall.SIGKILL)
	}
	res, err := RestoreRun(ctx, cfg, "the dead-man: "+why)
	if err != nil {
		return err
	}
	if res.Verdict != Clean {
		return fmt.Errorf("the dead-man restored: %s", res.Verdict)
	}
	return nil
}

// armed says the run's dead-man is armed and alive.
func armed(runDir *os.File) error {
	b, err := trusteddir.ReadFile(runDir, armedFile)
	if err != nil {
		return err
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return errors.New("its armed file is unreadable")
	}
	pid, err1 := strconv.Atoi(f[0])
	start, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 != nil || err2 != nil || !sameProcess(pid, start) {
		return errors.New("it isn't running")
	}
	return nil
}
