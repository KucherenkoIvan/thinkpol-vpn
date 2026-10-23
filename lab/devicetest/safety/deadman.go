//go:build darwin || linux

package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// The dead-man's files in a run's directory.
const (
	// stopFile disarms the dead-man: a restore is done.
	stopFile = "deadman.stop"
	// armedFile says the dead-man watches: "<pid> <start>".
	armedFile = "deadman.armed"
	// heartbeatFile changes each time a restore makes progress, never on
	// a timer: a hung restore lets it go stale.
	heartbeatFile = "restore.heartbeat"
)

// beat says the restore made progress.
func (h *host) beat() {
	if h.runDir == nil {
		return
	}
	h.beats++
	_ = trusteddir.WriteFile(h.runDir, heartbeatFile, fmt.Appendf(nil, "%d %d\n", os.Getpid(), h.beats))
}

// deadmanConfig is when the dead-man restores.
type deadmanConfig struct {
	// helperPID and helperStart are the helper it watches.
	helperPID   int
	helperStart int64
	// deadline is the plan's budget: past it, the dead-man restores
	// unless a restore is making progress.
	deadline time.Duration
	// limit is when it restores whatever the heartbeat says (default:
	// deadline + 10 min).
	limit time.Duration
	// stale is how long a heartbeat counts as fresh (default 60 s).
	stale time.Duration
	// poll is how often it looks (default 500 ms).
	poll time.Duration
}

func (c deadmanConfig) withDefaults() deadmanConfig {
	if c.limit == 0 {
		c.limit = c.deadline + 10*time.Minute
	}
	if c.stale == 0 {
		c.stale = time.Minute
	}
	if c.poll == 0 {
		c.poll = 500 * time.Millisecond
	}
	return c
}

// elapsedSince is the time since a start read both ways: monotonic (mono,
// which setting the clock can't move) and wall-clock (wall, with no
// monotonic reading, which keeps counting while a Mac sleeps and its
// monotonic clock stops). The larger counts: a sleep can't hold the
// dead-man past its budget, and setting the clock back can't either.
func elapsedSince(mono, wall, now time.Time) time.Duration {
	return max(now.Sub(mono), now.Round(0).Sub(wall))
}

// watch watches a run until its stop file appears (false) or the run must
// be restored (true, and why): the helper is gone without the stop file,
// the deadline has passed with no fresh heartbeat, or the limit has
// passed. The heartbeat is judged by when its content last changed, not
// by its file's time.
func watch(ctx context.Context, runDir *os.File, cfg deadmanConfig) (bool, string) {
	cfg = cfg.withDefaults()
	mono := time.Now()
	wall := mono.Round(0)
	var beat string
	var lastBeat time.Time
	tick := time.NewTicker(cfg.poll)
	defer tick.Stop()
	for {
		if exists(runDir, stopFile) {
			return false, ""
		}
		if b, err := trusteddir.ReadFile(runDir, heartbeatFile); err == nil && string(b) != beat {
			beat, lastBeat = string(b), time.Now()
		}
		why := ""
		switch elapsed := elapsedSince(mono, wall, time.Now()); {
		case !running(cfg.helperPID, cfg.helperStart):
			why = "the helper is gone"
		case elapsed >= cfg.limit:
			why = fmt.Sprintf("the limit (%v) has passed", cfg.limit)
		case elapsed >= cfg.deadline && (lastBeat.IsZero() || time.Since(lastBeat) > cfg.stale):
			why = fmt.Sprintf("the deadline (%v) has passed with no restore making progress", cfg.deadline)
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

// exists says name is in dir: only a successful look counts, so an error
// (EMFILE, EIO) never reads as the stop file.
func exists(dir *os.File, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil
}

// deadman is the dead-man process of a run: it says it is armed, watches,
// and restores the run from its journal when it must, the helper killed
// first if it is still the helper.
func deadman(ctx context.Context, cfg stateConfig, run string, dm deadmanConfig) error {
	runDir, err := cfg.openRun(run)
	if err != nil {
		return err
	}
	defer func() { _ = runDir.Close() }()
	start, err := startTime(os.Getpid())
	if err != nil {
		return err
	}
	if err := trusteddir.WriteFile(runDir, armedFile, fmt.Appendf(nil, "%d %d\n", os.Getpid(), start)); err != nil {
		return err
	}
	fire, why := watch(ctx, runDir, dm)
	if !fire {
		return nil
	}
	if running(dm.helperPID, dm.helperStart) {
		_ = syscall.Kill(dm.helperPID, syscall.SIGKILL)
	}
	res, err := restoreRun(ctx, cfg, "the dead-man: "+why)
	if err != nil {
		return err
	}
	if res.Verdict != Clean {
		return fmt.Errorf("the dead-man restored: %s", res.Verdict)
	}
	return nil
}

// armed says the run's dead-man is armed and running.
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
	if err1 != nil || err2 != nil || !running(pid, start) {
		return errors.New("it isn't running")
	}
	return nil
}
