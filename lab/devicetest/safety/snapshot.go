//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// Surface is one part of the host a snapshot records, read with one
// command.
type Surface struct {
	Name string
	Argv []string
	// Norm reads the output into the lines compared with the baseline;
	// nil records the output only.
	Norm func(output) ([]string, error)
	// Info: a difference is reported but doesn't count as left over (the
	// system changes it by itself, or the core doesn't own it).
	Info bool
	// Next is what to do when it differs.
	Next string
}

// Snapshot is the host's surfaces at one moment, normalised. The raw
// output is in the evidence folder (snapshots/<name>/).
type Snapshot struct {
	Name       string              `json:"name"`
	Taken      time.Time           `json:"taken"`
	Lines      map[string][]string `json:"lines"`
	Unreadable map[string]string   `json:"unreadable,omitempty"`
}

// Snapshot reads every surface, saves the raw output as evidence (when
// there is somewhere to write it), and keeps the normalised form in the
// run's directory, where a later restore finds the baseline.
func (h *Host) Snapshot(ctx context.Context, name string) (*Snapshot, error) {
	s := &Snapshot{Name: name, Taken: time.Now().UTC(), Lines: map[string][]string{}, Unreadable: map[string]string{}}
	for _, sf := range h.surfaceList() {
		out := run(ctx, sf.Argv, nil)
		h.saveOutput("snapshots/"+name+"/"+sf.Name, sf.Argv, out)
		if sf.Norm == nil {
			continue
		}
		lines, err := sf.Norm(out)
		if err != nil {
			s.Unreadable[sf.Name] = err.Error()
			continue
		}
		s.Lines[sf.Name] = lines
	}
	h.beat()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return s, trusteddir.WriteFile(h.RunDir, snapshotFile(name), b)
}

func snapshotFile(name string) string { return "snapshot-" + name + ".json" }

// loadSnapshot reads a snapshot back from the run's directory.
func loadSnapshot(h *Host, name string) (*Snapshot, error) {
	b, err := trusteddir.ReadFile(h.RunDir, snapshotFile(name))
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", snapshotFile(name), err)
	}
	return &s, nil
}

// saveOutput saves what one command printed: base.out, base.err, and
// base.json with the command, its exit status and why it failed. stderr is
// never dropped.
func (h *Host) saveOutput(base string, argv []string, out output) {
	if h.Evidence == nil {
		return
	}
	meta, _ := json.MarshalIndent(struct {
		Argv []string  `json:"argv"`
		Code int       `json:"exit"`
		Err  string    `json:"error,omitempty"`
		At   time.Time `json:"at"`
	}{argv, out.Code, out.Err, time.Now().UTC()}, "", "  ")
	for suffix, data := range map[string][]byte{".out": out.Stdout, ".err": out.Stderr, ".json": meta} {
		if err := h.Evidence.WriteFile(base+suffix, data); err != nil {
			h.log("evidence: %v", err)
		}
	}
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

func (d Difference) String() string {
	if d.Unreadable != "" {
		return fmt.Sprintf("%s: unreadable: %s", d.Surface, d.Unreadable)
	}
	return fmt.Sprintf("%s: %d lines gone, %d new (%s)", d.Surface, len(d.Missing), len(d.Extra),
		strings.Join(append(slices.Clone(d.Missing), d.Extra...), " | "))
}

// Diff compares now with base, surface by surface: the lines in order. A
// surface unreadable in either is a difference: it can't be shown equal.
func Diff(sfs []Surface, base, now *Snapshot) []Difference {
	var out []Difference
	for _, sf := range sfs {
		if sf.Norm == nil {
			continue
		}
		d := Difference{Surface: sf.Name, Info: sf.Info, Next: sf.Next}
		b, bok := base.Lines[sf.Name]
		n, nok := now.Lines[sf.Name]
		switch {
		case !bok:
			d.Unreadable = "at the baseline: " + base.Unreadable[sf.Name]
		case !nok:
			d.Unreadable = now.Unreadable[sf.Name]
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

// surfaceList is what h's snapshots read: the OS's surfaces unless a test
// gave its own.
func (h *Host) surfaceList() []Surface {
	if h.Surfaces != nil {
		return h.Surfaces
	}
	return surfaces()
}
