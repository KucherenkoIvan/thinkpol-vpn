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
// takes a name ending in a letter as a prefix, so `set skip on lo` skips
// lo0: TP-096 skips lo to see what pf and the guard make of it. Its undo
// loads /etc/pf.conf, so the change is refused unless the rules
// loaded now are the baseline's, nothing is skipped (loading pf.conf
// would drop a skip someone else loaded), and every rule the baseline
// had is one /etc/pf.conf loads (`pfctl -n`). That checks the baseline's
// rules are among pf.conf's, not that they are all of them: a pf.conf
// edited and not loaded yet makes the undo load rules the baseline didn't
// have, a false REBOOT, never a false CLEAN. It never flushes, disables
// or edits anything.
type pfSkipAction struct {
	Iface string `json:"iface"`
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
	return fmt.Sprintf("while %s is skipped: pfctl -f %s, once more if pf still differs from the baseline; never a flush", a.Iface, pfConfPath)
}

// pfConfControls are the surfaces loading /etc/pf.conf sets: the undo
// reloads until they match the baseline.
var pfConfControls = []string{"pf-rules", "pf-nat", "pf-skip"}

// pre refuses unless the loaded rules are the baseline's, nothing is
// skipped, and the baseline's rules are among what /etc/pf.conf loads
// (`pfctl -n` parses it and loads nothing): otherwise the undo would
// replace someone's rules or skips.
func (a *pfSkipAction) pre(ctx context.Context, h *host) error {
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

func (a *pfSkipAction) apply(ctx context.Context, h *host, _ func(json.RawMessage) error) error {
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
	return nil
}

// undo decides by the skipped interfaces against the baseline (which pre
// required to be pf.conf's, with nothing skipped), never by the name: the
// kernel's prefix rule lists `set skip on lo` as lo0. Skipped as at the
// baseline, there is nothing to undo (a reboot, or another app's load,
// took the skip away), and loading pf.conf now would replace what was
// loaded since. Otherwise, in the run's boot, it loads /etc/pf.conf until
// what that sets matches the baseline, at most twice; in a later boot it
// loads nothing (that boot isn't the run's to change) and fails, so the
// run isn't reset by the reboot. The restore's comparison judges the rest.
func (a *pfSkipAction) undo(ctx context.Context, h *host, laterBoot bool) (string, error) {
	if h.baseline == nil {
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
	for range 2 {
		argv := []string{pfctlPath, "-f", pfConfPath}
		out := h.run(ctx, argv, nil)
		h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.restore", time.Now().UnixNano()), argv, out)
		h.beat()
		if d := h.differs(ctx, pfConfControls); len(d) == 0 {
			return "loaded " + pfConfPath, nil
		}
	}
	return "", fmt.Errorf("%w (%v): %s", errPfSurvivedReload, h.differs(ctx, pfConfControls), nextPfReload)
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
