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

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
)

// KindPfMain is PfMainAction's kind.
const KindPfMain = "pf-main"

// PfMainAction loads the main pf ruleset as one line followed by the
// stock rules (/etc/pf.conf): TP-096's `set skip on lo`. Its undo loads
// /etc/pf.conf, so it is refused unless the rules loaded now are the
// stock ones. It never flushes, disables or edits anything.
type PfMainAction struct {
	Prepend string `json:"prepend"`
}

func decodePfMain(params json.RawMessage) (Action, error) {
	return decodeStrict[*PfMainAction](params)
}

func (a *PfMainAction) validate() error {
	if a.Prepend == "" || len(a.Prepend) > 200 {
		return errors.New("pf-main: one line of 1 to 200 characters")
	}
	for _, r := range a.Prepend {
		if r < 0x20 || r > 0x7e {
			return errors.New("pf-main: printable ASCII only, one line")
		}
	}
	return nil
}

func (*PfMainAction) Kind() string       { return KindPfMain }
func (*PfMainAction) Lifetime() Lifetime { return Volatile }
func (a *PfMainAction) Does() string {
	return fmt.Sprintf("load pf's main ruleset: %q, then %s", a.Prepend, pfConfPath)
}
func (*PfMainAction) UndoText() string {
	return "pfctl -f " + pfConfPath + ", once more if pf still differs from the baseline; never a flush"
}

// pfStock are the surfaces a load of /etc/pf.conf must put back.
var pfStock = []string{"pf-rules", "pf-nat", "pf-skip", "pf-anchor-250.ApplicationFirewall", "pf-anchor-200.AirDrop"}

// Pre refuses unless the rules loaded now are the baseline's and the
// baseline's are what /etc/pf.conf loads (pfctl -n parses it and loads
// nothing): otherwise the undo would replace someone's rules.
func (a *PfMainAction) Pre(ctx context.Context, h *Host) error {
	if h.Baseline == nil {
		return errors.New("no baseline")
	}
	if err := rootFile(pfConfPath); err != nil {
		return err
	}
	for _, name := range []string{"pf-rules", "pf-nat"} {
		now, err := h.read(ctx, name)
		if err != nil {
			return err
		}
		if !slices.Equal(now, h.Baseline.Lines[name]) {
			return fmt.Errorf("%s differs from the baseline", name)
		}
	}
	argv := []string{pfctlPath, "-n", "-v", "-f", pfConfPath}
	out := run(ctx, argv, nil)
	h.saveOutput(fmt.Sprintf("actions/pf-main-%d.stock-parse", time.Now().UnixNano()), argv, out)
	if out.Code != 0 {
		return fmt.Errorf("pfctl -n -f %s: %w", pfConfPath, failed(out))
	}
	stock := firewall.ListingLines(out.Stdout)
	for _, l := range append(slices.Clone(h.Baseline.Lines["pf-rules"]), h.Baseline.Lines["pf-nat"]...) {
		if !slices.Contains(stock, l) {
			return fmt.Errorf("the loaded rule %q isn't one %s loads", l, pfConfPath)
		}
	}
	return nil
}

func (a *PfMainAction) Apply(ctx context.Context, h *Host) (json.RawMessage, error) {
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return nil, err
	}
	argv := []string{pfctlPath, "-f", "-"}
	out := run(ctx, argv, append([]byte(a.Prepend+"\n"), conf...))
	h.saveOutput(fmt.Sprintf("actions/pf-main-%d.load", time.Now().UnixNano()), argv, out)
	if out.Code != 0 || out.Err != "" {
		return nil, fmt.Errorf("pfctl -f -: %w", failed(out))
	}
	return nil, nil
}

// Undo loads the stock rules until pf matches the baseline, at most twice
// (the runbook's "After a pf main-ruleset reload").
func (a *PfMainAction) Undo(ctx context.Context, h *Host) error {
	if h.Baseline == nil {
		return errors.New("no baseline to compare pf with: run sudo pfctl -f /etc/pf.conf by hand")
	}
	for range 2 {
		if d := h.differs(ctx, pfStock); len(d) == 0 {
			return nil
		}
		argv := []string{pfctlPath, "-f", pfConfPath}
		out := run(ctx, argv, nil)
		h.saveOutput(fmt.Sprintf("actions/pf-main-%d.restore", time.Now().UnixNano()), argv, out)
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
func (h *Host) read(ctx context.Context, name string) ([]string, error) {
	for _, sf := range h.surfaceList() {
		if sf.Name == name && sf.Norm != nil {
			return sf.Norm(run(ctx, sf.Argv, nil))
		}
	}
	return nil, fmt.Errorf("no surface %q", name)
}

// differs are those of the surfaces names that differ from the baseline
// now (or can't be read).
func (h *Host) differs(ctx context.Context, names []string) []string {
	var out []string
	for _, n := range names {
		now, err := h.read(ctx, n)
		if err != nil || !slices.Equal(now, h.Baseline.Lines[n]) {
			out = append(out, n)
		}
	}
	return out
}
