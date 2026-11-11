package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// The pf machinery the IPv6 guard and the kill switch share: pf enabled
// by a reference of an owner's own (pfEnabler), and the readers, the
// state kill and the flush over an owner's anchor and table. Each owner
// names itself in their errors, and wraps errNoPfctl into its own
// unsupported error (routetable.ErrGuardUnsupported,
// ErrKillSwitchUnsupported).

// errNoPfctl: there is no pfctl to run at all; the OS can't hold an
// owner's anchor.
var errNoPfctl = errors.New("firewall: no pfctl")

// pfEnabler holds pf enabled by a reference of its owner's own (`pfctl
// -E`), recorded in tokens as soon as it is taken, and releases it (`pfctl
// -X`) only while `pfctl -s References` lists it as taken by the pfctl the
// record names: the guard's and the kill switch's, each with its own
// record (package doc, "macOS: enabling pf by reference").
type pfEnabler struct {
	pf     pfctl
	tokens tokenStore
	// stale is told whenever pf's states need checking anew: pf seen off,
	// or a new reference taken.
	stale func()
	// token is the reference held (nil: none); a zero value is one whose
	// token `pfctl -E` didn't print readably, known by its pid only.
	// recorded says the record has it as it is.
	token    *pfToken
	recorded bool
	// owed are references held before takeReference replaced them, still
	// listed for all it knows: their release waits for the record to name
	// the new one (owed past takeReference when that write failed), a
	// failed release keeps them, and releaseAll releases them too.
	owed []pfToken
}

// hostAddrs are the addresses of the host's interfaces.
func hostAddrs() ([]netip.Addr, error) {
	ifas, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ifa := range ifas {
		if n, ok := ifa.(*net.IPNet); ok {
			if a, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	return out, nil
}

// checkHook reads pf's main ruleset (`pfctl -s rules`) and fails with an
// ordinary error, retried, when it doesn't evaluate the anchors under
// com.apple: the system may not have loaded /etc/pf.conf yet (an agent
// started at boot), or someone replaced it and may put the hook back.
func checkHook(ctx context.Context, pf pfctl) ([]byte, error) {
	out, err := pf.run(ctx, nil, "-s", "rules")
	if err != nil {
		return nil, err
	}
	if _, err := readLines(out.stdout); err != nil {
		return nil, err
	}
	if hooked(out.stdout) == hookMissing {
		return nil, fmt.Errorf("firewall: pf's main ruleset has no `anchor %s`: the system hasn't loaded /etc/pf.conf yet, or it was replaced; waiting for the hook", appleHook)
	}
	return out.stdout, nil
}

// rulesOf runs `pfctl -a anchor -s rules` (with -v if verbose): its
// stdout, or nil and exists false for an anchor that doesn't exist
// (AnchorMissing). Any other failure is an error.
func rulesOf(ctx context.Context, pf pfctl, anchor string, verbose bool) (rules []byte, exists bool, err error) {
	args := []string{"-a", anchor, "-s", "rules"}
	if verbose {
		args = append(args, "-v")
	}
	out, err := pf.run(ctx, nil, args...)
	if err != nil {
		if AnchorMissing(out.stderr) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return out.stdout, true, nil
}

// errNoTable: the table doesn't exist.
var errNoTable = errors.New("firewall: pf's table doesn't exist")

// listTable lists owner's table name of anchor (parseTableOf: both
// families, or IPv6 only); errNoTable when pf answers it doesn't exist.
func listTable(ctx context.Context, pf pfctl, anchor, name string, both bool, owner string) ([]netip.Prefix, error) {
	out, err := pf.run(ctx, nil, "-a", anchor, "-t", name, "-T", "show")
	if err != nil {
		if noTable(out.stderr) {
			return nil, fmt.Errorf("%w (the %s's %s): %w", errNoTable, owner, name, err)
		}
		return nil, err
	}
	table, err := parseTableOf(out.stdout, both)
	if err != nil {
		return nil, fmt.Errorf("the %s's %s: %w", owner, name, err)
	}
	return table, nil
}

func (pe *pfEnabler) enabled(ctx context.Context) (bool, error) {
	out, err := pe.pf.run(ctx, nil, "-s", "info")
	if err != nil {
		return false, err
	}
	return parseEnabled(out.stdout)
}

// references reads `pfctl -s References` (parseReferences).
func (pe *pfEnabler) references(ctx context.Context) ([]pfReference, bool, error) {
	out, err := pe.pf.run(ctx, nil, "-s", "References")
	if err != nil {
		return nil, false, fmt.Errorf("firewall: pf's references: %w", err)
	}
	refs, understood := parseReferences(out)
	return refs, understood, nil
}

// errUnreadToken: pfctl -E took a reference whose token neither its
// output nor pf's listing gives; it is recorded by pid, and Apply and
// Close fail until the token is known or the reference is gone. While pf
// is on, Apply enforces first (enable's after).
var errUnreadToken = errors.New("firewall: pf's enable token is unknown")

// resolve finds the token of t, a reference known by its pid only: the
// token pf lists for that pid. ok false with a nil error: pf's listing,
// readable, has no reference of that pid any more.
func (pe *pfEnabler) resolve(ctx context.Context, t pfToken) (uint64, bool, error) {
	refs, understood, err := pe.references(ctx)
	if err != nil {
		return 0, false, err
	}
	if !understood {
		return 0, false, fmt.Errorf("%w (pfctl pid %d): %w", errUnreadToken, t.pid, errUnreadReferences)
	}
	if v, ok := byPid(refs, t.pid); ok {
		return v, true, nil
	}
	if slices.ContainsFunc(refs, func(r pfReference) bool { return r.pid == t.pid }) {
		return 0, false, fmt.Errorf("%w (pfctl pid %d)", errUnreadToken, t.pid)
	}
	return 0, false, nil
}

// errUnreadReferences: `pfctl -s References` printed a listing thinkpol
// can't read, in which a reference's absence proves nothing.
var errUnreadReferences = errors.New("firewall: pf's references listed in a form thinkpol can't read")

// enable makes sure pf is on with a reference of its owner's, and the
// record names it: kept while pf is on; taken over from the record (a
// crashed run's, this boot); taken anew when it has none, or when
// pf is off (someone ran `pfctl -d`), the old one then released if pf
// still lists it. after is what leaves pf on and the owner's reference
// recorded, which the caller goes on enforcing through and tells after:
// that release's failure, and errUnreadToken while pf is on (by the new
// reference, or with the one known by pid only). With pf off, an
// unread token is err: the bypass check and the kill would vouch for
// states pf goes on passing.
func (pe *pfEnabler) enable(ctx context.Context) (after, err error) {
	on, err := pe.enabled(ctx)
	if err != nil {
		return nil, err
	}
	if !on {
		// What pf passed while off needs checking once it is on again,
		// whatever stops this Apply first.
		pe.stale()
	}
	if err := pe.adoptRecord(); err != nil {
		return nil, err
	}
	if rerr := pe.resolveToken(ctx); rerr != nil {
		if on && errors.Is(rerr, errUnreadToken) {
			// pf is on: enforce, then tell the token.
			if err := pe.recordToken(); err != nil {
				return nil, err
			}
			return errors.Join(rerr, pe.releaseOwed(ctx)), nil
		}
		return nil, rerr
	}
	if on && pe.token != nil {
		if err := pe.recordToken(); err != nil {
			return nil, err
		}
		return pe.releaseOwed(ctx), nil
	}
	// pf off (marked above), or on without a reference of the owner's
	// (someone else's, or a plain `pfctl -e`): states it holds from then
	// need checking.
	pe.stale()
	return pe.takeReference(ctx)
}

// adoptRecord takes over the reference the record names (a crashed
// run's, this boot) when it holds none and doesn't owe it, and
// removes a stale record.
func (pe *pfEnabler) adoptRecord() error {
	if pe.token != nil {
		return nil
	}
	t, state, err := pe.tokens.read()
	switch {
	case err != nil:
		return err
	case state == recordHeld && slices.Contains(pe.owed, t):
		// A failed write left the record naming a reference this owner
		// replaced: owed, not held. The next write replaces the record.
		return nil
	case state == recordHeld:
		pe.token, pe.recorded = &t, true
	case state == recordStale:
		return pe.tokens.remove()
	}
	return nil
}

// resolveToken finds the token of a reference it knows by its pid
// only; one pf no longer lists is dropped, and its record replaced by the
// next reference's.
func (pe *pfEnabler) resolveToken(ctx context.Context) error {
	if pe.token == nil || pe.token.value != 0 {
		return nil
	}
	t, err := pe.resolvedToken(ctx, pe.token)
	if err != nil {
		return err
	}
	pe.token, pe.recorded = t, false
	return nil
}

// resolvedToken is t with its token found when t is known by its pid
// only; nil when pf no longer lists that pid's reference (or t is nil).
func (pe *pfEnabler) resolvedToken(ctx context.Context, t *pfToken) (*pfToken, error) {
	if t == nil || t.value != 0 {
		return t, nil
	}
	v, ok, err := pe.resolve(ctx, *t)
	if err != nil || !ok {
		return nil, err
	}
	return &pfToken{value: v, pid: t.pid}, nil
}

// recordToken writes the owner's reference to the record, unless it is
// there already.
func (pe *pfEnabler) recordToken() error {
	if pe.recorded {
		return nil
	}
	if err := pe.tokens.write(*pe.token); err != nil {
		return err
	}
	pe.recorded = true
	return nil
}

// takeReference turns pf on with a new reference (`pfctl -E`) and
// records it, then releases the one it held, if pf still lists it
// (releaseOwed). after: what went wrong once pf is on by the new, recorded
// reference (the old one's release, the new token unread); err: pf not
// enabled, or the reference not recorded, the old one then owed still.
func (pe *pfEnabler) takeReference(ctx context.Context) (after, err error) {
	old := pe.token
	out, err := pe.pf.run(ctx, nil, "-E")
	if err != nil {
		return nil, fmt.Errorf("firewall: enable pf: %w", err)
	}
	if old != nil {
		pe.owed = append(pe.owed, *old)
	}
	t := pfToken{pid: out.pid}
	v, perr := parseToken(out)
	var rerr error
	if perr == nil {
		t.value = v
	} else if v, ok, err := pe.resolve(ctx, t); ok {
		t.value = v
	} else {
		rerr = err
	}
	pe.token, pe.recorded = &t, false
	if err := pe.recordToken(); err != nil {
		return nil, err
	}
	after = pe.releaseOwed(ctx)
	if t.value == 0 {
		after = errors.Join(after, unreadToken(t.pid, perr, rerr))
	}
	return after, nil
}

// releaseOwed releases the references it held before pf was enabled
// anew (owed), now that the record names the new one: pf was off
// although it held them. If pfctl -d left them listed, they go now
// that pf is on again (pf refuses -X while off); best effort: enforcing
// goes on first. A release that fails (a References listing it can't
// read, pfctl failing or cut short) is told after, and that reference
// stays owed: the next Apply or Close retries it.
func (pe *pfEnabler) releaseOwed(ctx context.Context) error {
	var errs []error
	var kept []pfToken
	for _, old := range pe.owed {
		if err := pe.release(ctx, old); err != nil {
			kept = append(kept, old)
			errs = append(errs, fmt.Errorf("firewall: pf enabled anew, but releasing the reference it held before failed (pid %d): %w", old.pid, err))
		}
	}
	pe.owed = kept
	return errors.Join(errs...)
}

// unreadToken is errUnreadToken for the reference pfctl pid took, with
// why neither its output (perr) nor pf's listing (rerr; nil: the listing,
// readable, has no reference of that pid) gave the token. resolve's
// errUnreadToken names the pid already.
func unreadToken(pid int, perr, rerr error) error {
	switch {
	case errors.Is(rerr, errUnreadToken):
		return fmt.Errorf("%w; %w", rerr, perr)
	case rerr != nil:
		return fmt.Errorf("%w (pfctl pid %d): %w; %w", errUnreadToken, pid, perr, rerr)
	}
	return fmt.Errorf("%w (pfctl pid %d): %w", errUnreadToken, pid, perr)
}

// release lets go of t, a reference with a known token: `pfctl -X` if pf
// lists it as taken by the pfctl the record names, nothing if it isn't
// listed (gone already) or is someone else's (the value was reused).
func (pe *pfEnabler) release(ctx context.Context, t pfToken) error {
	refs, understood, err := pe.references(ctx)
	if err != nil {
		return err
	}
	if !understood {
		// Not listed in a listing it can't read proves nothing:
		// fail, so Close keeps the record and a later one retries.
		return errUnreadReferences
	}
	if referenced(refs, t) != refOurs {
		return nil
	}
	if _, err := pe.pf.run(ctx, nil, "-X", fmt.Sprint(t.value)); err != nil {
		return fmt.Errorf("firewall: release pf's reference: %w", err)
	}
	return nil
}

// killStates kills the states pf holds between an address of the host
// (own) and one allowed doesn't take, IPv6 only or (both) of either
// family, each by its two ends and the reverse; loopback is left alone.
// what says whose refusal it is, for the error.
func killStates(ctx context.Context, pf pfctl, ownAddrs func() ([]netip.Addr, error), allowed func(netip.Addr) bool, both bool, what string) error {
	out, err := pf.run(ctx, nil, "-s", "states")
	if err != nil {
		return fmt.Errorf("firewall: pf's states: %w", err)
	}
	states, err := parseStatesOf(out.stdout, both)
	if err != nil {
		return fmt.Errorf("firewall: pf's states: %w", err)
	}
	if len(states) == 0 {
		return nil
	}
	own, err := ownAddrs()
	if err != nil {
		return fmt.Errorf("firewall: the host's addresses: %w", err)
	}
	type pair struct{ local, remote netip.Addr }
	var pairs []pair
	for _, addrs := range states {
		var local, remote []netip.Addr
		for _, x := range addrs {
			if slices.Contains(own, x) {
				local = append(local, x)
			} else {
				remote = append(remote, x)
			}
		}
		for _, l := range local {
			for _, r := range remote {
				if !r.IsLoopback() && !allowed(r) {
					pairs = append(pairs, pair{l, r})
				}
			}
		}
	}
	slices.SortFunc(pairs, func(x, y pair) int {
		if c := x.local.Compare(y.local); c != 0 {
			return c
		}
		return x.remote.Compare(y.remote)
	})
	for _, p := range slices.Compact(pairs) {
		for _, args := range [][]string{{"-k", p.local.String(), "-k", p.remote.String()}, {"-k", p.remote.String(), "-k", p.local.String()}} {
			if _, err := pf.run(ctx, nil, args...); err != nil {
				return fmt.Errorf("firewall: kill pf's states %s: %w", what, err)
			}
		}
	}
	return nil
}

// flushAnchor empties owner's anchor: its rules, then its table table
// (of both families, or IPv6 only); `-F all` would also flush pf's
// global state table and statistics. Whatever each -F answered,
// succeeded or failed (what pfctl answers for an anchor that doesn't
// exist is unrecorded), the anchor's listing after it decides: no rule
// listed (an anchor that doesn't exist lists none, AnchorMissing), then
// no table (noTable), is empty; anything else, a listing that fails
// included, fails it with the -F's error and the listing's. With no
// pfctl it fails with errNoPfctl, for the owner to translate.
func flushAnchor(ctx context.Context, pf pfctl, anchor, table string, both bool, owner string) error {
	noRules := func(ctx context.Context) error {
		b, _, err := rulesOf(ctx, pf, anchor, false)
		if err != nil {
			return err
		}
		rules, err := readLines(b)
		if err == nil && len(rules) > 0 {
			err = fmt.Errorf("firewall: pf still lists %d rules in the %s's anchor", len(rules), owner)
		}
		return err
	}
	tableGone := func(ctx context.Context) error {
		_, err := listTable(ctx, pf, anchor, table, both, owner)
		switch {
		case errors.Is(err, errNoTable):
			return nil
		case err == nil:
			return fmt.Errorf("firewall: pf still holds the %s's table %s", owner, table)
		}
		return err
	}
	for _, step := range []struct {
		modifier string
		empty    func(context.Context) error
	}{{"rules", noRules}, {"Tables", tableGone}} {
		_, err := pf.run(ctx, nil, "-a", anchor, "-F", step.modifier)
		if errors.Is(err, errNoPfctl) {
			return err
		}
		if lerr := step.empty(ctx); lerr != nil {
			return fmt.Errorf("firewall: remove the %s: %w", owner, errors.Join(err, lerr))
		}
	}
	return nil
}

// releaseAll releases the references still owed, then the one held, or
// the one the record holds from this boot (a crashed run's), and removes
// the record. The owed go first: pf stays on by the held reference while
// they are released (pf refuses -X while off). A failure, a reference
// whose token can't be found included, keeps the record for a later try.
func (pe *pfEnabler) releaseAll(ctx context.Context) error {
	t := pe.token
	if t == nil {
		rec, state, err := pe.tokens.read()
		if err != nil {
			return err
		}
		if state == recordHeld {
			t = &rec
		}
	}
	t, err := pe.resolvedToken(ctx, t)
	if err != nil {
		return err
	}
	for len(pe.owed) > 0 {
		if err := pe.release(ctx, pe.owed[0]); err != nil {
			return err
		}
		pe.owed = pe.owed[1:]
	}
	if t != nil {
		if err := pe.release(ctx, *t); err != nil {
			return err
		}
	}
	return pe.forget()
}

// forget removes the record and the references held.
func (pe *pfEnabler) forget() error {
	if err := pe.tokens.remove(); err != nil {
		return err
	}
	pe.token, pe.recorded, pe.owed = nil, false, nil
	return nil
}
