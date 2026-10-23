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
// by the stock rules (/etc/pf.conf), which keeps Apple's hook: a skip on
// a name no interface has, to see what pf and the guard make of it. Its
// undo loads /etc/pf.conf, so it is
// refused unless the rules loaded now are the baseline's, those are what
// /etc/pf.conf loads, and nothing is skipped (the undo would drop a skip
// someone else loaded). It never flushes, disables or edits anything.
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
func (*pfSkipAction) kind() string       { return KindPfSkip }
func (*pfSkipAction) lifetime() lifetime { return volatile }
func (a *pfSkipAction) does() string {
	return fmt.Sprintf("load pf's main ruleset: %q, then %s", a.line(), pfConfPath)
}
func (*pfSkipAction) undoText() string {
	return "pfctl -f " + pfConfPath + ", once more if pf still differs from the baseline; never a flush"
}

// pfStock are the surfaces a load of /etc/pf.conf must put back.
var pfStock = []string{"pf-rules", "pf-nat", "pf-skip", "pf-anchor-250.ApplicationFirewall", "pf-anchor-200.AirDrop"}

// pre refuses unless the loaded rules are the baseline's, nothing is
// skipped, and the baseline's rules are what /etc/pf.conf loads (`pfctl -n`
// parses it and loads nothing): otherwise the undo would replace someone's
// rules or skips.
func (a *pfSkipAction) pre(ctx context.Context, h *host) error {
	if h.baseline == nil {
		return errors.New("no baseline")
	}
	if err := rootFile(pfConfPath); err != nil {
		return err
	}
	for _, name := range []string{"pf-rules", "pf-nat", "pf-skip"} {
		now, err := h.read(ctx, name)
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
	out := run(ctx, argv, nil)
	h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.stock-parse", time.Now().UnixNano()), argv, out)
	if out.Code != 0 || out.Err != "" {
		return fmt.Errorf("pfctl -n -f %s: %w", pfConfPath, failed(out))
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
	out := run(ctx, argv, append([]byte(a.line()+"\n"), conf...))
	h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.load", time.Now().UnixNano()), argv, out)
	if out.Code != 0 || out.Err != "" {
		return fmt.Errorf("pfctl -f -: %w", failed(out))
	}
	return nil
}

// undo loads the stock rules until pf matches the baseline, at most twice.
func (a *pfSkipAction) undo(ctx context.Context, h *host) error {
	if h.baseline == nil {
		return errors.New("no baseline to compare pf with: run sudo pfctl -f /etc/pf.conf by hand")
	}
	for range 2 {
		if d := h.differs(ctx, pfStock); len(d) == 0 {
			return nil
		}
		argv := []string{pfctlPath, "-f", pfConfPath}
		out := run(ctx, argv, nil)
		h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.restore", time.Now().UnixNano()), argv, out)
		h.beat()
	}
	if d := h.differs(ctx, pfStock); len(d) > 0 {
		return fmt.Errorf("pf differs from the baseline after two loads of %s (%v): %s", pfConfPath, d, nextPfReload)
	}
	return nil
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

// read reads one surface now.
func (h *host) read(ctx context.Context, name string) ([]string, error) {
	for _, sf := range h.surfaceList() {
		if sf.name == name && sf.norm != nil {
			return sf.norm(run(ctx, sf.argv, nil))
		}
	}
	return nil, fmt.Errorf("no surface %q", name)
}

// differs are those of the surfaces names that differ from the baseline
// now (or can't be read).
func (h *host) differs(ctx context.Context, names []string) []string {
	var out []string
	for _, n := range names {
		now, err := h.read(ctx, n)
		if err != nil || !slices.Equal(now, h.baseline.Lines[n]) {
			out = append(out, n)
		}
	}
	return out
}
