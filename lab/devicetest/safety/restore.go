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
	"slices"
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
	// what to do. The run stays pending until a restore finds it clean.
	Left = "LEFT"
	// Reboot: what is left lives only in the kernel and the core won't
	// remove it by hand (pf): a reboot clears it. Pending, like Left.
	Reboot = "REBOOT"
	// Nothing: there was nothing to restore (no run pending, or a run
	// that didn't start); nothing was compared.
	Nothing = "NOTHING-TO-RESTORE"
	// ResetByReboot: a pending run restored in a later boot, with no
	// change of its own left in its journal: each was undone or went with
	// the boot it was made in. What still differs from the baseline is the
	// new boot's, not the run's. Never CLEAN; the run is closed.
	ResetByReboot = "RESET-BY-REBOOT"
	// Forgotten: a pending run the owner closed by name in a later boot
	// (`devicetest restore -forget RUN`), after being shown what its
	// journal and the comparison still say. Nothing was proven; the run
	// is closed.
	Forgotten = "FORGOTTEN"
)

// closes says a restore with verdict v closes its run: the next run may
// start. Any other verdict keeps the run pending.
func closes(v string) bool {
	return v == Clean || v == Nothing || v == ResetByReboot || v == Forgotten
}

// Result is what a restore did and what it found.
type Result struct {
	Verdict        string       `json:"verdict"`
	By             string       `json:"by"`
	Run            string       `json:"run,omitempty"`
	Undone         []string     `json:"undone,omitempty"`
	Failed         []string     `json:"failed,omitempty"`
	GoneWithReboot []string     `json:"gone_with_reboot,omitempty"`
	Left           []Difference `json:"left,omitempty"`
	Info           []Difference `json:"info,omitempty"`
	Notes          []string     `json:"notes,omitempty"`
}

// restore undoes every pending change, newest first, lets the host settle
// (the OS's waits go with the OS's surfaces), and compares it with the
// baseline in a fresh snapshot.
func (e *engine) restore(ctx context.Context, by string) Result {
	res := Result{By: by}
	e.h.beat()
	for _, en := range e.j.pending() {
		err := e.undo(ctx, en)
		switch {
		case err != nil:
			res.Failed = append(res.Failed, err.Error())
		case e.entry(en.Seq).State == stateGoneWithBoot:
			res.GoneWithReboot = append(res.GoneWithReboot, fmt.Sprintf("%d: %s", en.Seq, en.Does))
		default:
			res.Undone = append(res.Undone, fmt.Sprintf("%d: %s", en.Seq, en.Does))
		}
	}
	if e.h.baseline == nil && e.h.baselineErr == nil && len(e.j.entries()) == 0 {
		res.Verdict = Nothing
		res.Notes = append(res.Notes, "no baseline was taken and nothing was changed: nothing to compare")
		return res
	}
	if e.h.surfaces == nil {
		res.Notes = append(res.Notes, settle(ctx, e.h)...)
	}
	e.compare(ctx, &res)
	res.Verdict = verdict(res)
	return res
}

func (e *engine) compare(ctx context.Context, res *Result) {
	switch {
	case e.h.baselineErr != nil:
		res.Failed = append(res.Failed, fmt.Sprintf("the baseline can't be read back (%v): reboot, then run devicetest restore", e.h.baselineErr))
		return
	case e.h.baseline == nil:
		res.Failed = append(res.Failed, "no baseline was taken, yet the journal names changes: the host can't be compared with what it was")
		return
	}
	after, err := e.h.snapshot(ctx, afterName)
	if err != nil {
		res.Failed = append(res.Failed, "the snapshot after the restore: "+err.Error())
		return
	}
	for _, d := range diff(e.h.surfaceList(), e.h.baseline, after) {
		if d.Info {
			res.Info = append(res.Info, d)
		} else {
			res.Left = append(res.Left, d)
		}
	}
}

func verdict(r Result) string {
	for _, d := range r.Left {
		if d.reboot {
			return Reboot
		}
	}
	if len(r.Failed) > 0 || len(r.Left) > 0 {
		return Left
	}
	return Clean
}

// stateConfig is where runs keep their journals: a directory of root's,
// checked like every directory on its way (trusteddir).
type stateConfig struct {
	dir string
	// allowNonRoot, surfaces and exec are the core's tests': a user's
	// directory, surfaces that never read the host's pf, and a runner
	// that runs no host tool.
	allowNonRoot bool
	surfaces     []surface
	exec         runner
}

func defaultState() stateConfig { return stateConfig{dir: defaultStateDir} }

// The state directory's files.
const (
	// activeFile names the run that started and isn't restored yet.
	activeFile = "active"
	// leftFile names the run whose restore wasn't CLEAN: it stays pending
	// until a restore finds the host clean.
	leftFile    = "left"
	lockFile    = "devicetest.lock"
	runInfoFile = "run.json"
	resultFile  = "result.json"
	// keepRuns is how many runs' directories the state directory keeps
	// (the owner's choice); older ones are pruned when a run starts.
	keepRuns = 10
)

var runID = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z-]{0,63}$`)

func (c stateConfig) open() (*os.File, error) {
	if !c.allowNonRoot && os.Geteuid() != 0 {
		return nil, errors.New("the core runs as root (devicetest starts it with sudo)")
	}
	return trusteddir.Make(c.dir)
}

func (c stateConfig) openRun(run string) (*os.File, error) {
	if !runID.MatchString(run) {
		return nil, fmt.Errorf("bad run id %q", run)
	}
	state, err := c.open()
	if err != nil {
		return nil, err
	}
	_ = state.Close()
	return trusteddir.Open(filepath.Join(c.dir, "run-"+run))
}

// lock takes the state directory's lock, waiting up to timeout for a
// helper that is being killed to let it go.
func (c stateConfig) lock(state *os.File, timeout time.Duration) (*os.File, error) {
	deadline := time.Now().Add(timeout)
	for {
		l, err := trusteddir.Lock(state, lockFile)
		if !errors.Is(err, trusteddir.ErrLocked) || time.Now().After(deadline) {
			return l, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// pendingRun is the run waiting for a restore: the active one, else the
// one left not clean; "" if none. A pointer that can't be read is an
// error, never "none".
func pendingRun(state *os.File) (string, error) {
	for _, name := range []string{activeFile, leftFile} {
		b, err := trusteddir.ReadFile(state, name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		run := strings.TrimSpace(string(b))
		if !runID.MatchString(run) {
			return "", fmt.Errorf("%s names %q", name, run)
		}
		return run, nil
	}
	return "", nil
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

// restoreRun restores the pending run from its journal: the dead-man's
// (only, its own run: only names it) and `devicetest restore`'s way (only
// ""). A run of an earlier boot has its volatile changes skipped (gone
// with that boot) and its persistent ones undone; a run left not clean is
// compared with its baseline again. A run of an earlier boot with no
// change of its own left pending is closed, RESET-BY-REBOOT, when it
// isn't CLEAN.
func restoreRun(ctx context.Context, cfg stateConfig, by, only string) (Result, error) {
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
	run, err := pendingRun(state)
	if err != nil {
		return Result{}, err
	}
	if run == "" {
		return Result{Verdict: Nothing, By: by, Notes: []string{"no run is pending a restore"}}, nil
	}
	if only != "" && run != only {
		return Result{Verdict: Nothing, By: by, Notes: []string{fmt.Sprintf("the run pending a restore is %s, not %s: left to devicetest restore", run, only)}}, nil
	}
	o, err := openRunForRestore(cfg, run)
	if err != nil {
		return Result{}, err
	}
	res := (&engine{h: o.h, j: o.j, armed: refuseChanges}).restore(ctx, by)
	res.Notes = append(res.Notes, o.notes...)
	if !closes(res.Verdict) && o.info.Boot != o.h.boot && len(o.j.pending()) == 0 {
		res.Verdict = ResetByReboot
		res.Notes = append(res.Notes, fmt.Sprintf("the run was in another boot (%s) and no change of its own is left in its journal: "+
			"each was undone or went with that boot, so what differs is this boot's, not the run's", o.info.Boot))
	}
	err = finish(state, o, &res)
	return res, err
}

// openedRun is a run's directory, journal and record, open; notes say
// what couldn't be opened on the way.
type openedRun struct {
	h     *host
	j     *journal
	info  runInfo
	notes []string
}

func openRunForRestore(cfg stateConfig, run string) (openedRun, error) {
	boot, err := trusteddir.BootSession()
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
	o := openedRun{info: info}
	h := &host{runDir: runDir, boot: boot, runBoot: info.Boot, surfaces: cfg.surfaces, exec: cfg.exec}
	if ev, err := openEvidence(info.Evidence, info.UID, info.GID); err == nil {
		h.evidence = ev
	} else {
		o.notes = append(o.notes, fmt.Sprintf("the evidence folder %s won't open (%v): this result is in root's run directory only", info.Evidence, err))
	}
	h.baseline, h.baselineErr = loadSnapshot(h, baselineName)
	if errors.Is(h.baselineErr, fs.ErrNotExist) {
		h.baselineErr = nil // never taken: the run stopped before it
	}
	j, err := openJournal(runDir, boot)
	if err != nil {
		return openedRun{}, err
	}
	o.h, o.j = h, j
	return o, nil
}

// finish ends a restore: the result kept (the run's directory and the
// evidence), the journal copied into the evidence, the dead-man disarmed,
// the root copy deleted. A verdict that closes the run (closes) closes the
// journal and clears both pointers; any other leaves the run pending
// (leftFile) for the next restore, and no run may start meanwhile. The
// active pointer goes only once the left one is on disk: a pending run is
// never left unnamed.
func finish(state *os.File, o openedRun, res *Result) error {
	res.Run = o.info.Run
	b, _ := json.MarshalIndent(res, "", "  ")
	errs := []error{trusteddir.WriteFile(o.h.runDir, resultFile, b)}
	if o.h.evidence != nil {
		errs = append(errs, o.h.evidence.writeFile(fmt.Sprintf("restore/result-%d.json", time.Now().UnixNano()), b))
	}
	if closes(res.Verdict) {
		errs = append(errs, o.j.close())
	} else {
		errs = append(errs, o.j.release())
	}
	if o.h.evidence != nil {
		if jb, err := trusteddir.ReadFile(o.h.runDir, journalName); err == nil {
			errs = append(errs, o.h.evidence.writeFile(fmt.Sprintf("journal/journal-%d.jsonl", time.Now().UnixNano()), jb))
		}
	}
	errs = append(errs, trusteddir.WriteFile(o.h.runDir, stopFile, []byte("restored\n")))
	if closes(res.Verdict) {
		errs = append(errs, trusteddir.Remove(state, leftFile), trusteddir.Remove(state, activeFile), fullSync(state))
	} else if err := errors.Join(trusteddir.WriteFile(state, leftFile, []byte(o.info.Run+"\n")), fullSync(state)); err != nil {
		errs = append(errs, fmt.Errorf("the run stays active (its left pointer isn't on disk): %w", err))
	} else {
		errs = append(errs, trusteddir.Remove(state, activeFile), fullSync(state))
	}
	errs = append(errs, removeRootCopy(o.info.RootCopy))
	return errors.Join(errs...)
}

// prune removes the oldest runs' directories so that, with the one about
// to start, keepRuns remain. It runs only when no run is pending a
// restore (openRunState), so it never removes a pending one. A directory
// holding anything but regular files (a symlink, a directory) is left.
// The evidence folders are the owner's and never pruned.
func prune(state *os.File) error {
	ents, err := state.ReadDir(-1)
	if _, serr := state.Seek(0, 0); err == nil {
		err = serr
	}
	if err != nil {
		return err
	}
	var runs []string
	for _, e := range ents {
		if name := e.Name(); e.IsDir() && strings.HasPrefix(name, "run-") {
			runs = append(runs, name)
		}
	}
	slices.Sort(runs) // run ids start with their UTC start time
	var errs []error
	for len(runs) > keepRuns-1 {
		errs = append(errs, removeRunDir(state, runs[0]))
		runs = runs[1:]
	}
	return errors.Join(errs...)
}

func removeRunDir(state *os.File, name string) error {
	fd, err := unix.Openat(int(state.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("prune %s: %w", name, err)
	}
	d := os.NewFile(uintptr(fd), name)
	defer func() { _ = d.Close() }()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("prune %s: %w", name, err)
	}
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("prune %s: %s isn't a regular file: left", name, n)
		}
		if err := unix.Unlinkat(fd, n, 0); err != nil {
			return fmt.Errorf("prune %s: %w", name, err)
		}
	}
	return unix.Unlinkat(int(state.Fd()), name, unix.AT_REMOVEDIR)
}
