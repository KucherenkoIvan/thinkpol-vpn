//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// surface is one part of the host a snapshot records, read with one
// command.
type surface struct {
	name string
	argv []string
	// norm reads the output into the lines compared with the baseline;
	// nil records the output only.
	norm func(output) ([]string, error)
	// info: a difference is reported but doesn't count as left over (the
	// system changes it by itself, or the core doesn't own it).
	info bool
	// next is what to do when it differs.
	next string
}

// snapshot is the host's surfaces at one moment, normalised. The raw
// output is in the evidence folder (snapshots/<name>/).
type snapshot struct {
	Name       string              `json:"name"`
	Taken      time.Time           `json:"taken"`
	Lines      map[string][]string `json:"lines"`
	Unreadable map[string]string   `json:"unreadable,omitempty"`
}

// The snapshots' names: only the core chooses them.
const (
	baselineName = "00-baseline"
	afterName    = "99-after-restore"
)

// snapshot reads every surface and keeps the normalised form in the run's
// directory (where a later restore finds the baseline), written once: a
// baseline that exists is never replaced, and an after-restore snapshot
// of a later restore takes the next free name (-2, -3...). The raw output
// goes to the evidence when there is somewhere to write it.
func (h *host) snapshot(ctx context.Context, base string) (*snapshot, error) {
	f, name, err := h.reserveSnapshot(base)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	s := &snapshot{Name: name, Taken: time.Now().UTC(), Lines: map[string][]string{}, Unreadable: map[string]string{}}
	for _, sf := range h.surfaceList() {
		out := h.run(ctx, sf.argv, nil)
		h.beat() // each surface may take commandTimeout: a slow one is progress
		h.saveOutput("snapshots/"+name+"/"+sf.name, sf.argv, out)
		if sf.norm == nil {
			continue
		}
		lines, err := sf.norm(out)
		if err != nil {
			s.Unreadable[sf.name] = fmt.Sprintf("%v (exit %d, stdout %q, stderr %q)", err, out.Code, clip(out.Stdout), clip(out.Stderr))
			continue
		}
		s.Lines[sf.name] = lines
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err == nil {
		_, err = f.Write(b)
	}
	if err = errors.Join(err, fullSync(f), fullSync(h.runDir)); err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", name, err)
	}
	return s, nil
}

// reserveSnapshot creates the snapshot's file in the run's directory,
// exclusively: base itself for the baseline, the first free of base,
// base-2, base-3... otherwise.
func (h *host) reserveSnapshot(base string) (*os.File, string, error) {
	for i := 1; i < 100; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		fd, err := unix.Openat(int(h.runDir.Fd()), snapshotFile(name), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return os.NewFile(uintptr(fd), filepath.Join(h.runDir.Name(), snapshotFile(name))), name, nil
		}
		if !errors.Is(err, unix.EEXIST) || base == baselineName {
			return nil, "", fmt.Errorf("snapshot %s: %w", name, err)
		}
	}
	return nil, "", fmt.Errorf("snapshot %s: no free name", base)
}

func snapshotFile(name string) string { return "snapshot-" + name + ".json" }

// clip is b's start, enough to quote in a result.
func clip(b []byte) string {
	const max = 300
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

// loadSnapshot reads a snapshot back from the run's directory.
func loadSnapshot(h *host, name string) (*snapshot, error) {
	b, err := trusteddir.ReadFile(h.runDir, snapshotFile(name))
	if err != nil {
		return nil, err
	}
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", snapshotFile(name), err)
	}
	return &s, nil
}

// saveOutput saves what one command printed: base.out, base.err, and
// base.json with the command, its exit status and why it failed. stderr is
// never dropped.
func (h *host) saveOutput(base string, argv []string, out output) {
	if h.evidence == nil {
		return
	}
	meta, _ := json.MarshalIndent(struct {
		Argv []string  `json:"argv"`
		Code int       `json:"exit"`
		Err  string    `json:"error,omitempty"`
		At   time.Time `json:"at"`
	}{argv, out.Code, out.Err, time.Now().UTC()}, "", "  ")
	for suffix, data := range map[string][]byte{".out": out.Stdout, ".err": out.Stderr, ".json": meta} {
		if err := h.evidence.writeFile(base+suffix, data); err != nil {
			h.log("evidence: %v", err)
		}
	}
}

// surfaceList is what h's snapshots read: the OS's surfaces unless a test
// gave its own.
func (h *host) surfaceList() []surface {
	if h.surfaces != nil {
		return h.surfaces
	}
	return surfaces()
}

// Difference is how a surface differs from the baseline.
type Difference struct {
	Surface    string   `json:"surface"`
	Missing    []string `json:"missing,omitempty"`
	Extra      []string `json:"extra,omitempty"`
	Unreadable string   `json:"unreadable,omitempty"`
	Info       bool     `json:"info,omitempty"`
	Next       string   `json:"next,omitempty"`
}

// diff compares now with base, surface by surface: the lines in order. A
// surface unreadable in either is a difference: it can't be shown equal.
func diff(sfs []surface, base, now *snapshot) []Difference {
	var out []Difference
	for _, sf := range sfs {
		if sf.norm == nil {
			continue
		}
		d := Difference{Surface: sf.name, Info: sf.info, Next: sf.next}
		b, bok := base.Lines[sf.name]
		n, nok := now.Lines[sf.name]
		switch {
		case !bok:
			d.Unreadable = "at the baseline: " + base.Unreadable[sf.name]
		case !nok:
			d.Unreadable = now.Unreadable[sf.name]
		case slices.Equal(b, n):
			continue
		default:
			d.Missing, d.Extra = lineDiff(b, n)
			if len(d.Missing) == 0 && len(d.Extra) == 0 {
				d.Extra = []string{"(the same lines in another order)"}
			}
		}
		out = append(out, d)
	}
	return out
}

// lineDiff is the lines of a not in b, and of b not in a, counted as a
// multiset.
func lineDiff(a, b []string) (missing, extra []string) {
	count := map[string]int{}
	for _, l := range a {
		count[l]++
	}
	for _, l := range b {
		if count[l] > 0 {
			count[l]--
			continue
		}
		extra = append(extra, l)
	}
	for _, l := range a {
		if count[l] > 0 {
			count[l]--
			missing = append(missing, l)
		}
	}
	return missing, extra
}

// listingLines are a listing's non-empty lines, trimmed: every line kept,
// so a comparison drops nothing.
func listingLines(b []byte) []string {
	lines := []string{}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
