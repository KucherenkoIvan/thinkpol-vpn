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
// CLEAN. On a Mac whose pfctl marks no skipped interface, the skip checks
// (the precondition's and the undo's) see nothing, so a ruleset of
// another app's that is the stock rules plus a skip of its own can be
// loaded over, and every run there ends LEFT, never CLEAN (doc.go). It
// never flushes, disables or edits anything.
type pfSkipAction struct {
	Iface string `json:"iface"`
	// Loaded, Rules, Nat and Skips: what the run's load left in pf's main
	// rules, nat rules and skipped interfaces, journaled once it has run
	// (learnt). The undo reloads only while all three are still what pf
	// holds.
	Loaded bool     `json:"loaded,omitempty"`
	Rules  []string `json:"rules,omitempty"`
	Nat    []string `json:"nat,omitempty"`
	Skips  []string `json:"skips,omitempty"`
	// Failed: why apply stopped before it could journal what the load
	// left (the load failed, or pf couldn't be read after it), journaled
	// instead, so the undo's LEFT names the cause.
	Failed string `json:"failed,omitempty"`
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
	return fmt.Sprintf("while pf holds the rules, nat and skips this load set, unless the skip pf listed after it is gone: pfctl -f %s, "+
		"once more if the skip alone still differs from the baseline; a skip pf never listed: pfctl -f %s once, then LEFT; never a flush",
		pfConfPath, pfConfPath)
}

// pfConfControls are the surfaces loading /etc/pf.conf sets: the undo
// reloads until they match the baseline.
var pfConfControls = []string{"pf-rules", "pf-nat", "pf-skip"}

// pre refuses unless the loaded rules are the baseline's, nothing is
// skipped, and the baseline's rules, of which there is at least one, are
// among what /etc/pf.conf loads (`pfctl -n` parses it and loads nothing):
// otherwise the undo would replace someone's rules or skips. An empty
// listing would make that last check prove nothing. A spec naming what a
// load set is refused: only apply learns that. The skips check sees
// nothing on a Mac whose pfctl marks no skipped interface (the type's
// doc).
func (a *pfSkipAction) pre(ctx context.Context, h *host) error {
	if a.Loaded || a.Rules != nil || a.Nat != nil || a.Skips != nil || a.Failed != "" {
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
	if len(h.baseline.Lines["pf-rules"]) == 0 {
		return errors.New("pf's main rules listed nothing at the baseline: whether they are among what pf.conf loads can't be checked")
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
// left in pf's main rules, nat rules and skipped interfaces (learnt). If
// any of that can't be read or journaled, the undo never learns it, and
// fails LEFT; when apply itself fails before that, it journals why
// (Failed), and the LEFT says so.
func (a *pfSkipAction) apply(ctx context.Context, h *host, learnt func(json.RawMessage) error) error {
	fail := func(err error) error {
		params, merr := json.Marshal(pfSkipAction{Iface: a.Iface, Failed: err.Error()})
		if merr == nil {
			merr = learnt(params)
		}
		return errors.Join(err, merr)
	}
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return fail(fmt.Errorf("reading %s failed, before any load: %w", pfConfPath, err))
	}
	argv := []string{pfctlPath, "-f", "-"}
	out := h.run(ctx, argv, append([]byte(a.line()+"\n"), conf...))
	h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.load", time.Now().UnixNano()), argv, out)
	if err := checked(out); err != nil {
		return fail(fmt.Errorf("the load failed: pfctl -f -: %w", err))
	}
	rules, nat, skips, err := h.pfLoaded(ctx)
	if err != nil {
		return fail(fmt.Errorf("reading pf after the load failed: %w", err))
	}
	params, err := json.Marshal(pfSkipAction{Iface: a.Iface, Loaded: true, Rules: rules, Nat: nat, Skips: skips})
	if err != nil {
		return err
	}
	return learnt(params)
}

// undo decides by the skipped interfaces against the baseline (which pre
// required to be pf.conf's, with nothing skipped), never by the name: the
// kernel's prefix rule lists `set skip on lo` as lo0. In a later boot it
// loads nothing (that boot isn't the run's to change): skipped as at the
// baseline, the change went with the boot; otherwise it fails, so the run
// isn't reset by the reboot. In the run's boot it never takes the skip
// for gone unless pf listed it after the run's load and lists it no
// longer (another app's load took it away: a reboot would make this a
// later boot); so it fails LEFT, loading nothing, when the load's outcome
// was never journaled (the load may have run: it failed, the helper died,
// or reading pf after it failed). It reloads /etc/pf.conf only while pf's
// main rules, nat rules and skipped interfaces are all still what the
// run's load left: otherwise another app has loaded its own ruleset
// since, perhaps with its own skips, and loading pf.conf would wipe it,
// so it fails without loading. A skip pf never listed, even right after
// the load, can't be shown gone: it reloads once and fails LEFT, and the
// reboot that clears it closes the run. Otherwise it loads once, and a
// second time only when the skip alone still differs from the baseline
// (with rules or nat differing too, another load can't help, and would
// wipe a ruleset loaded in between), and decides on the read after the
// last load; the restore's comparison judges the rest. What it can't tell
// from its own load: another app's that left exactly the same rules, nat
// and skips (on a Mac whose pfctl marks no skipped interface, any skips
// look the same: there it reloads once over such a ruleset and fails
// LEFT), or one that lands between its check and its reload. That
// ruleset is replaced by pf.conf's, and the comparison can't see it went
// (doc.go).
func (a *pfSkipAction) undo(ctx context.Context, h *host, laterBoot bool) (string, error) {
	switch {
	case h.baseline == nil && laterBoot:
		return "", errors.New("no baseline to compare pf with, in a later boot than the run's: nothing loaded; reboot, or devicetest restore -forget")
	case h.baseline == nil:
		return "", errors.New("no baseline to compare pf with: nothing loaded; reboot, then devicetest restore")
	}
	skips, err := h.readSurface(ctx, "pf-skip")
	if err != nil {
		return "", fmt.Errorf("pf's skipped interfaces: %w", err)
	}
	base := h.baseline.Lines["pf-skip"]
	switch {
	case laterBoot && slices.Equal(skips, base):
		return "gone with its boot: pf skips what it did at the baseline", nil
	case laterBoot:
		return "", fmt.Errorf("pf skips %v, not the baseline's %v, in a later boot than the run's: nothing loaded in a boot the run never touched; reboot, or devicetest restore -forget", skips, base)
	case !a.Loaded:
		why := "the helper stopped before journaling it, or the journal write failed"
		if a.Failed != "" {
			why = a.Failed
		}
		return "", fmt.Errorf("what the load of %q left in pf was never journaled (%s), "+
			"so this run's ruleset can't be told from another app's, nor its skip shown gone: nothing loaded; %s", a.line(), why, nextPfUnproven)
	case slices.Equal(skips, base) && !slices.Equal(a.Skips, base):
		return "nothing to do: pf skips what it did at the baseline (the skip was gone already)", nil
	}
	rules, nat, _, err := h.pfLoaded(ctx)
	if err != nil {
		return "", fmt.Errorf("pf's rules: %w", err)
	}
	if !slices.Equal(rules, a.Rules) || !slices.Equal(nat, a.Nat) || !slices.Equal(skips, a.Skips) {
		return "", fmt.Errorf("pf skips %v, but its rules, nat or skips aren't the ones this run's load set: another ruleset was loaded since, "+
			"and loading %s would wipe it, so nothing was loaded: %s", skips, pfConfPath, nextPfOtherRuleset)
	}
	if slices.Equal(a.Skips, base) {
		out := h.load(ctx)
		return "", fmt.Errorf("pf listed no skipped interface even right after this run's load of %q, so whether that skip is gone can't be read "+
			"(loaded %s once: %v): %s", a.line(), pfConfPath, nilOr(checked(out), "ok"), nextPfUnproven)
	}
	h.load(ctx)
	d, times := h.differs(ctx, pfConfControls), "once"
	if slices.Equal(d, []string{"pf-skip"}) {
		h.load(ctx)
		d, times = h.differs(ctx, pfConfControls), "twice"
	}
	switch {
	case len(d) == 0:
		return "loaded " + pfConfPath, nil
	case slices.Contains(d, "pf-skip"):
		return "", fmt.Errorf("%w (%v): %s", errPfSurvivedReload, d, nextPfReload)
	}
	return "", fmt.Errorf("the skip is gone, but %v differ from the baseline after loading %s %s: "+
		"pf.conf may have changed since it was last loaded, or another app loaded a ruleset in between", d, pfConfPath, times)
}

// load loads /etc/pf.conf, its output saved, and beats.
func (h *host) load(ctx context.Context) output {
	argv := []string{pfctlPath, "-f", pfConfPath}
	out := h.run(ctx, argv, nil)
	h.saveOutput(fmt.Sprintf("actions/pf-skip-%d.restore", time.Now().UnixNano()), argv, out)
	h.beat()
	return out
}

// pfLoaded reads what loading a ruleset sets that the undo goes by: pf's
// main rules, nat rules and skipped interfaces.
func (h *host) pfLoaded(ctx context.Context) (rules, nat, skips []string, err error) {
	rules, rerr := h.readSurface(ctx, "pf-rules")
	nat, nerr := h.readSurface(ctx, "pf-nat")
	skips, serr := h.readSurface(ctx, "pf-skip")
	return rules, nat, skips, errors.Join(rerr, nerr, serr)
}

// nilOr is err's text, or ok when err is nil.
func nilOr(err error, ok string) string {
	if err == nil {
		return ok
	}
	return err.Error()
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
