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

// forgetRun closes the pending run, named by the owner, in a later boot
// than the run's (in its own boot, `devicetest restore` is the way, or a
// reboot first). When the journal reads back, the restore runs first, so
// only what no undo could close is forgotten: a change of its own that
// can't be undone. When it doesn't, the host is compared and the journal
// closed as it is. The result, FORGOTTEN, keeps what the undos did, what
// the journal still says and the comparison, and proves nothing; it is
// kept in the run's directory and the evidence like any result. A run
// whose record or directory can't be opened is beyond it (safety's
// doc.go, "Verdicts").
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
	o, err := openRunForRestore(cfg, run)
	if err != nil {
		return Result{By: by, Run: run}, err
	}
	if o.info.Boot == o.h.boot {
		return Result{By: by, Run: run}, fmt.Errorf("run %s started in this boot: run devicetest restore, or reboot first (a run is forgotten only in a later boot)", run)
	}
	var res Result
	if o.journalErr == nil {
		res = (&engine{h: o.h, j: o.j, armed: refuseChanges}).restore(ctx, by)
		res.Notes = append(res.Notes, o.notes...)
		o.resetByReboot(&res)
		if closes(res.Verdict) {
			res.Notes = append(res.Notes, "the restore closed the run itself: nothing was forgotten")
			return res, finish(state, o, &res)
		}
	} else {
		res = Result{By: by, Notes: append([]string{"the journal doesn't read back: " + o.journalErr.Error()}, o.notes...)}
		if o.h.surfaces == nil {
			res.Notes = append(res.Notes, settle(ctx, o.h)...)
		}
		(&engine{h: o.h}).compare(ctx, &res)
		if o.j, err = appendOnlyJournal(o.h.runDir, run, o.h.boot); err != nil {
			return res, err
		}
	}
	res.Verdict = Forgotten
	res.Notes = append(res.Notes, "forgotten at the owner's request, in a later boot than the run's: nothing here was proven")
	res.Notes = append(res.Notes, journalSays(o.h.runDir)...)
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
// it, or makes one if it is missing: a newline first ends a torn last
// line, so the closing line is a line of its own.
func appendOnlyJournal(runDir *os.File, run, boot string) (*journal, error) {
	path := filepath.Join(runDir.Name(), journalName)
	fd, err := unix.Openat(int(runDir.Fd()), journalName, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
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
