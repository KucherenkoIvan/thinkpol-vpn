package safety

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"
	"time"
)

// pfSkipAction loads pf's main ruleset as `set skip on <Iface>` followed
// by the stock rules (/etc/pf.conf, Apple's hook included). The kernel
// takes a name ending in a letter as a prefix of interfaces named it plus
// a number, so `set skip on lo` skips lo0. Its undo loads /etc/pf.conf, so
// the change is refused unless the rules loaded now are the baseline's,
// nothing is skipped (loading pf.conf would drop a skip someone else
// loaded), and every rule the baseline had is one /etc/pf.conf loads
// (`pfctl -n`). That checks the baseline's rules are among pf.conf's, not
// that they are all of them: a pf.conf edited and not loaded yet leaves
// rules the baseline didn't have after the undo, LEFT, never a false
// CLEAN. pf's limits, timeouts and debug level aren't checked: loading
// pf.conf resets them, so values another app set come out LEFT, never
// CLEAN. It never flushes, disables or edits anything.
type pfSkipAction struct {
	Iface string `json:"iface"`
	// Loaded, Rules and Nat: what the run's load left in pf's main and
	// nat rules, journaled once it has run (learnt). The undo reloads only
	// while they are still what pf holds.
	Loaded bool     `json:"loaded,omitempty"`
	Rules  []string `json:"rules,omitempty"`
	Nat    []string `json:"nat,omitempty"`
}

func decodePfSkip(params json.RawMessage) (action, error) {
	return decodeStrict[pfSkipAction](params)
}

func (a *pfSkipAction) validate() error {
	if !ifaceName.MatchString(a.Iface) {
		return fmt.Errorf("pf-skip: bad interface name %q", a.Iface)
	}
	return nil
}

func (a *pfSkipAction) line() string     { return "set skip on " + a.Iface }
func (*pfSkipAction) kind() string       { return kindPfSkip }
func (*pfSkipAction) lifetime() lifetime { return volatile }
func (a *pfSkipAction) does() string {
	return fmt.Sprintf("load pf's main ruleset: %q, then %s", a.line(), pfConfPath)
}
func (a *pfSkipAction) undoText() string {
	return fmt.Sprintf("while pf skips other than at the baseline and holds the rules this load set: pfctl -f %s, "+
		"once more if pf still differs from the baseline; never a flush", pfConfPath)
}

// pfConfControls are the surfaces loading /etc/pf.conf sets: the undo
// reloads until they match the baseline.
var pfConfControls = []string{"pf-rules", "pf-nat", "pf-skip"}

// pre refuses unless the loaded rules are the baseline's, nothing is
// skipped, and the baseline's rules are among what /etc/pf.conf loads
// (`pfctl -n` parses it and loads nothing): otherwise the undo would
// replace someone's rules or skips. A spec naming what a load set is
// refused: only apply learns that.
func (a *pfSkipAction) pre(ctx context.Context, h *host) error {
	if a.Loaded || a.Rules != nil || a.Nat != nil {
		return errors.New("pf-skip names no loaded rules before it runs")
	}
	if h.baseline == nil {
		return errors.New("no baseline")
	}
	if err := rootFile(pfConfPath); err != nil {
		return err
	}
	for _, name := range pfConfControls {
		now, err := h.readSurface(ctx, name)
		if err != nil {
			return err
		}
		if !slices.Equal(now, h.baseline.Lines[name]) {
			return fmt.Errorf("%s differs from the baseline", name)
		}
	}
	if skips := h.baseline.Lines["pf-skip"]; len(skips) > 0 {
		return fmt.Errorf("pf skips %v already: loading %s back would drop it", skips, pfConfPath)
	}
	argv := []string{pfctlPath, "-n", "-v", "-f", pfConfPath}
	out := h.run(ctx, argv, nil)
	h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.stock-parse", time.Now().UnixNano()), argv, out)
	if err := checked(out); err != nil {
		return fmt.Errorf("pfctl -n -f %s: %w", pfConfPath, err)
	}
	stock := listingLines(out.Stdout)
	for _, l := range append(slices.Clone(h.baseline.Lines["pf-rules"]), h.baseline.Lines["pf-nat"]...) {
		if !slices.Contains(stock, l) {
			return fmt.Errorf("the loaded rule %q isn't one %s loads", l, pfConfPath)
		}
	}
	return nil
}

// apply loads the skip and the stock rules, then journals what the load
// left in pf's main and nat rules (learnt).
func (a *pfSkipAction) apply(ctx context.Context, h *host, learnt func(json.RawMessage) error) error {
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return err
	}
	argv := []string{pfctlPath, "-f", "-"}
	out := h.run(ctx, argv, append([]byte(a.line()+"\n"), conf...))
	h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.load", time.Now().UnixNano()), argv, out)
	if err := checked(out); err != nil {
		return fmt.Errorf("pfctl -f -: %w", err)
	}
	rules, rerr := h.readSurface(ctx, "pf-rules")
	nat, nerr := h.readSurface(ctx, "pf-nat")
	if err := errors.Join(rerr, nerr); err != nil {
		return fmt.Errorf("pf's rules after the load: %w", err)
	}
	params, err := json.Marshal(pfSkipAction{Iface: a.Iface, Loaded: true, Rules: rules, Nat: nat})
	if err != nil {
		return err
	}
	return learnt(params)
}

// undo decides by the skipped interfaces against the baseline (which pre
// required to be pf.conf's, with nothing skipped), never by the name: the
// kernel's prefix rule lists `set skip on lo` as lo0. Skipped as at the
// baseline, there is nothing to undo (a reboot, or another app's load,
// took the skip away). In a later boot it loads nothing (that boot isn't
// the run's to change) and fails, so the run isn't reset by the reboot.
// In the run's boot it reloads /etc/pf.conf only while pf's main and nat
// rules are still what the run's load set (the baseline's, before that
// is journaled): otherwise another app has loaded its own ruleset since,
// perhaps with its own skips, and loading pf.conf would wipe it, so it
// fails without loading. It loads at most twice, until what pf.conf sets
// matches the baseline; the restore's comparison judges the rest.
func (a *pfSkipAction) undo(ctx context.Context, h *host, laterBoot bool) (string, error) {
	switch {
	case h.baseline == nil && laterBoot:
		return "", errors.New("no baseline to compare pf with, in a later boot than the run's: nothing loaded; reboot, or devicetest restore -forget")
	case h.baseline == nil:
		return "", errors.New("no baseline to compare pf with: run sudo pfctl -f /etc/pf.conf by hand")
	}
	skips, err := h.readSurface(ctx, "pf-skip")
	if err != nil {
		return "", fmt.Errorf("pf's skipped interfaces: %w", err)
	}
	base := h.baseline.Lines["pf-skip"]
	switch {
	case slices.Equal(skips, base) && laterBoot:
		return "gone with its boot: pf skips what it did at the baseline", nil
	case slices.Equal(skips, base):
		return "nothing to do: pf skips what it did at the baseline (the skip was gone already)", nil
	case laterBoot:
		return "", fmt.Errorf("pf skips %v, not the baseline's %v, in a later boot than the run's: nothing loaded in a boot the run never touched; reboot, or devicetest restore -forget", skips, base)
	}
	wantRules, wantNat := h.baseline.Lines["pf-rules"], h.baseline.Lines["pf-nat"]
	if a.Loaded {
		wantRules, wantNat = a.Rules, a.Nat
	}
	rules, rerr := h.readSurface(ctx, "pf-rules")
	nat, nerr := h.readSurface(ctx, "pf-nat")
	if err := errors.Join(rerr, nerr); err != nil {
		return "", fmt.Errorf("pf's rules: %w", err)
	}
	if !slices.Equal(rules, wantRules) || !slices.Equal(nat, wantNat) {
		return "", fmt.Errorf("pf skips %v, but its rules aren't the ones this run's load set: another ruleset was loaded since, "+
			"and loading %s would wipe it, so nothing was loaded: %s", skips, pfConfPath, nextPfOtherRuleset)
	}
	for range 2 {
		argv := []string{pfctlPath, "-f", pfConfPath}
		out := h.run(ctx, argv, nil)
		h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.restore", time.Now().UnixNano()), argv, out)
		h.beat()
		if d := h.differs(ctx, pfConfControls); len(d) == 0 {
			return "loaded " + pfConfPath, nil
		}
	}
	d := h.differs(ctx, pfConfControls)
	if slices.Contains(d, "pf-skip") {
		return "", fmt.Errorf("%w (%v): %s", errPfSurvivedReload, d, nextPfReload)
	}
	return "", fmt.Errorf("the skip is gone, but %v differ from the baseline after loading %s: was pf.conf changed after it was last loaded?", d, pfConfPath)
}

// rootFile checks path is a regular file of root's that no one else may
// write.
func rootFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: not a regular file only root may write", path)
	}
	return nil
}

// readSurface reads one surface now.
func (h *host) readSurface(ctx context.Context, name string) ([]string, error) {
	for _, sf := range h.surfaceList() {
		if sf.name == name && sf.norm != nil {
			return sf.norm(h.run(ctx, sf.argv, nil))
		}
	}
	return nil, fmt.Errorf("no surface %q", name)
}

// differs are those of the surfaces names that differ from the baseline
// now (or can't be read).
func (h *host) differs(ctx context.Context, names []string) []string {
	var out []string
	for _, n := range names {
		now, err := h.readSurface(ctx, n)
		if err != nil || !slices.Equal(now, h.baseline.Lines[n]) {
			out = append(out, n)
		}
	}
	return out
}
