//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// Verdicts of a restore.
const (
	// Clean: every change undone, and the host matches the baseline.
	Clean = "CLEAN"
	// Left: something differs or failed to undo; Result says what and
	// what to do.
	Left = "LEFT"
	// Reboot: what is left lives only in the kernel and the core won't
	// remove it by hand (pf): a reboot clears it.
	Reboot = "REBOOT"
)

// Result is what a restore did and what it found.
type Result struct {
	Verdict        string       `json:"verdict"`
	By             string       `json:"by"`
	Undone         []string     `json:"undone,omitempty"`
	Failed         []string     `json:"failed,omitempty"`
	GoneWithReboot []string     `json:"gone_with_reboot,omitempty"`
	Left           []Difference `json:"left,omitempty"`
	Info           []Difference `json:"info,omitempty"`
	Notes          []string     `json:"notes,omitempty"`
}

// Restore undoes every pending action, last first, lets the host settle
// (OS-specific: no agent left, pf's state as at the baseline), and
// compares it with the baseline.
func (e *Engine) Restore(ctx context.Context, by string) Result {
	res := Result{By: by}
	e.h.beat()
	for _, en := range e.j.Pending() {
		err := e.undo(ctx, en)
		switch {
		case err != nil:
			res.Failed = append(res.Failed, err.Error())
		case e.entry(en.Seq).State == StateGoneWithBoot:
			res.GoneWithReboot = append(res.GoneWithReboot, fmt.Sprintf("%d: %s", en.Seq, en.Does))
		default:
			res.Undone = append(res.Undone, fmt.Sprintf("%d: %s", en.Seq, en.Does))
		}
	}
	if e.h.Surfaces == nil { // the OS's waits go with the OS's surfaces
		res.Notes = append(res.Notes, settle(ctx, e.h)...)
	}
	e.compare(ctx, &res)
	res.Verdict = verdict(res)
	return res
}

func (e *Engine) compare(ctx context.Context, res *Result) {
	if e.h.Baseline == nil {
		if len(e.j.Entries()) > 0 {
			res.Failed = append(res.Failed, "no baseline: the host can't be compared with what it was")
		}
		res.Notes = append(res.Notes, "no baseline was taken")
		return
	}
	after, err := e.h.Snapshot(ctx, "99-after-restore")
	if err != nil {
		res.Failed = append(res.Failed, "the snapshot after the restore: "+err.Error())
		return
	}
	for _, d := range Diff(e.h.surfaceList(), e.h.Baseline, after) {
		if d.Info {
			res.Info = append(res.Info, d)
		} else {
			res.Left = append(res.Left, d)
		}
	}
}

func verdict(r Result) string {
	for _, d := range r.Left {
		if strings.HasPrefix(d.Surface, "pf-") && d.Surface != "pf-info" {
			return Reboot
		}
	}
	if len(r.Failed) > 0 || len(r.Left) > 0 {
		return Left
	}
	return Clean
}

// StateConfig is where runs keep their journals: a directory of root's,
// checked like every directory on its way (trusteddir).
type StateConfig struct {
	Dir string
	// AllowNonRoot lets the core's tests run it as a user, in a directory
	// of theirs. Never a flag of the command.
	AllowNonRoot bool
	// Surfaces are what snapshots read; nil: the OS's (for the core's
	// tests, like AllowNonRoot).
	Surfaces []Surface
}

// The state directory's files.
const (
	// activeFile names the run whose journal isn't closed: while it is
	// there, nothing but a restore may run.
	activeFile  = "active"
	lockFile    = "devicetest.lock"
	runInfoFile = "run.json"
	resultFile  = "result.json"
)

var runID = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z-]{0,63}$`)

func (c StateConfig) open() (*os.File, error) {
	if !c.AllowNonRoot && os.Geteuid() != 0 {
		return nil, errors.New("the core runs as root (it is started with sudo by devicetest)")
	}
	return trusteddir.Make(c.Dir)
}

func (c StateConfig) openRun(run string) (*os.File, error) {
	if !runID.MatchString(run) {
		return nil, fmt.Errorf("bad run id %q", run)
	}
	if _, err := c.open(); err != nil {
		return nil, err
	}
	return trusteddir.Open(filepath.Join(c.Dir, "run-"+run))
}

// lock takes the state directory's lock, waiting up to timeout for a
// helper that is being killed to let it go.
func (c StateConfig) lock(state *os.File, timeout time.Duration) (*os.File, error) {
	deadline := time.Now().Add(timeout)
	for {
		l, err := trusteddir.Lock(state, lockFile)
		if !errors.Is(err, trusteddir.ErrLocked) || time.Now().After(deadline) {
			return l, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Active is the run whose journal isn't closed, "" if none.
func (c StateConfig) Active() (string, error) {
	state, err := c.open()
	if err != nil {
		return "", err
	}
	defer func() { _ = state.Close() }()
	b, err := trusteddir.ReadFile(state, activeFile)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return strings.TrimSpace(string(b)), err
}

// runInfo is what a later restore needs to know of a run.
type runInfo struct {
	Run      string    `json:"run"`
	Evidence string    `json:"evidence"`
	UID      int       `json:"uid"`
	GID      int       `json:"gid"`
	RootCopy string    `json:"root_copy,omitempty"`
	Boot     string    `json:"boot"`
	Started  time.Time `json:"started"`
}

// RestoreRun restores the unfinished run from its journal: the dead-man's
// and `devicetest restore`'s way. A run of an earlier boot has its
// volatile changes skipped (gone with that boot) and its persistent ones
// undone.
func RestoreRun(ctx context.Context, cfg StateConfig, by string) (Result, error) {
	state, err := cfg.open()
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = state.Close() }()
	lk, err := cfg.lock(state, 15*time.Second)
	if err != nil {
		return Result{}, fmt.Errorf("another helper or restore runs: %w", err)
	}
	defer func() { _ = lk.Close() }()
	run, err := cfg.Active()
	if err != nil || run == "" {
		return Result{Verdict: Clean, By: by, Notes: []string{"no unfinished run"}}, err
	}
	o, err := openRunForRestore(cfg, run)
	if err != nil {
		return Result{}, err
	}
	res := NewEngine(o.h, o.j, nil).Restore(ctx, by)
	return res, finish(state, o.h, o.j, o.info, res)
}

type openedRun struct {
	h    *Host
	j    *Journal
	info runInfo
}

func openRunForRestore(cfg StateConfig, run string) (openedRun, error) {
	boot, err := bootSession()
	if err != nil {
		return openedRun{}, err
	}
	runDir, err := cfg.openRun(run)
	if err != nil {
		return openedRun{}, err
	}
	var info runInfo
	b, err := trusteddir.ReadFile(runDir, runInfoFile)
	if err == nil {
		err = json.Unmarshal(b, &info)
	}
	if err != nil {
		return openedRun{}, fmt.Errorf("%s: %w", runInfoFile, err)
	}
	h := &Host{RunDir: runDir, Boot: boot, Surfaces: cfg.Surfaces}
	if ev, err := OpenEvidence(info.Evidence, info.UID, info.GID); err == nil {
		h.Evidence = ev
	}
	if base, err := loadSnapshot(h, "00-baseline"); err == nil {
		h.Baseline = base
	}
	j, err := OpenJournal(runDir, boot)
	if err != nil {
		return openedRun{}, err
	}
	return openedRun{h: h, j: j, info: info}, nil
}

// finish closes a restored run: its result kept (the run's directory and
// the evidence), the journal closed and copied into the evidence, the
// dead-man disarmed, the active pointer removed, the root copy deleted.
func finish(state *os.File, h *Host, j *Journal, info runInfo, res Result) error {
	b, _ := json.MarshalIndent(res, "", "  ")
	errs := []error{trusteddir.WriteFile(h.RunDir, resultFile, b), j.Close()}
	if h.Evidence != nil {
		errs = append(errs, h.Evidence.WriteFile(fmt.Sprintf("restore/result-%d.json", time.Now().UnixNano()), b))
		if jb, err := trusteddir.ReadFile(h.RunDir, JournalName); err == nil {
			errs = append(errs, h.Evidence.WriteFile(fmt.Sprintf("journal/journal-%d.jsonl", time.Now().UnixNano()), jb))
		}
	}
	errs = append(errs, trusteddir.WriteFile(h.RunDir, stopFile, []byte("restored\n")))
	errs = append(errs, trusteddir.Remove(state, activeFile), unix.Fsync(int(state.Fd())))
	errs = append(errs, removeRootCopy(info.RootCopy))
	return errors.Join(errs...)
}
