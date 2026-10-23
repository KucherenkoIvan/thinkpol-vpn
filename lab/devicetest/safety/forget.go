//go:build darwin || linux

package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// forgetRun closes the pending run, named by the owner, that no restore
// can close: its journal doesn't read back, or a change of its own can't
// be undone. Only in a later boot than the run's (in its own boot,
// `devicetest restore` is the way, or a reboot first). The result,
// FORGOTTEN, shows what the journal can still say and how the host
// compares with the baseline now, and proves nothing; it is kept in the
// run's directory and the evidence like any result, the journal is
// closed and the run cleared.
func forgetRun(ctx context.Context, cfg stateConfig, run, by string) (Result, error) {
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
	pending, err := pendingRun(state)
	switch {
	case err != nil:
		return Result{}, err
	case pending == "":
		return Result{Verdict: Nothing, By: by, Notes: []string{"no run is pending a restore"}}, nil
	case pending != run:
		return Result{}, fmt.Errorf("the run pending a restore is %s, not %s", pending, run)
	}
	boot, err := trusteddir.BootSession()
	if err != nil {
		return Result{}, err
	}
	runDir, err := cfg.openRun(run)
	if err != nil {
		return Result{}, err
	}
	var info runInfo
	b, err := trusteddir.ReadFile(runDir, runInfoFile)
	if err == nil {
		err = json.Unmarshal(b, &info)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w: which boot the run was in is unknown, so it isn't forgotten", runInfoFile, err)
	}
	if info.Boot == boot {
		return Result{}, fmt.Errorf("run %s started in this boot: run devicetest restore, or reboot first (a run is forgotten only in a later boot)", run)
	}
	o := openedRun{info: info, h: &host{runDir: runDir, boot: boot, runBoot: info.Boot, surfaces: cfg.surfaces, exec: cfg.exec}}
	if ev, err := openEvidence(info.Evidence, info.UID, info.GID); err == nil {
		o.h.evidence = ev
	}
	res := Result{Verdict: Forgotten, By: by}
	res.Notes = append(res.Notes, "forgotten at the owner's request, in a later boot than the run's: nothing here was proven")
	res.Notes = append(res.Notes, journalSays(runDir)...)
	if o.h.baseline, err = loadSnapshot(o.h, baselineName); err != nil {
		res.Notes = append(res.Notes, "no comparison: the baseline can't be read back: "+err.Error())
	} else if after, err := o.h.snapshot(ctx, afterName); err != nil {
		res.Notes = append(res.Notes, "no comparison: the snapshot now: "+err.Error())
	} else {
		for _, d := range diff(o.h.surfaceList(), o.h.baseline, after) {
			if d.Info {
				res.Info = append(res.Info, d)
			} else {
				res.Left = append(res.Left, d)
			}
		}
	}
	if o.j, err = openJournal(runDir, boot); err != nil {
		if o.j, err = appendOnlyJournal(runDir, run, boot); err != nil {
			return res, err
		}
	}
	return res, finish(state, o, &res)
}

// journalSays is what a journal can still show, line by line: each change
// and its last state, and each line that doesn't read.
func journalSays(runDir *os.File) []string {
	data, err := trusteddir.ReadFile(runDir, journalName)
	if err != nil {
		return []string{"journal: " + err.Error()}
	}
	j := &journal{all: map[int]*entry{}}
	var out []string
	for i, raw := range bytes.Split(data, []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		var l line
		if err := json.Unmarshal(raw, &l); err != nil {
			out = append(out, fmt.Sprintf("journal line %d doesn't read: %v", i+1, err))
			continue
		}
		if l.Journal == "" {
			j.fold(l)
		}
	}
	for _, e := range j.entries() {
		out = append(out, fmt.Sprintf("journal: change %d (%s, %s, boot %s): %s", e.Seq, e.Does, e.Lifetime, e.Boot, e.State))
	}
	return out
}

// appendOnlyJournal opens a journal that doesn't read back, only to close
// it: a newline first ends a torn last line, so the closing line is a
// line of its own.
func appendOnlyJournal(runDir *os.File, run, boot string) (*journal, error) {
	path := filepath.Join(runDir.Name(), journalName)
	fd, err := unix.Openat(int(runDir.Fd()), journalName, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	if _, err := f.Write([]byte("\n")); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("journal: %w", err)
	}
	return &journal{f: f, run: run, boot: boot, all: map[int]*entry{}}, nil
}
