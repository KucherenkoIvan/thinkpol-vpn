package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// guardPoll is how often Watch reads the guard back from pf: pf has no
// event stream, so a flush, a disabled pf or a replaced main ruleset is
// seen within guardPoll (and a debounce) rather than at once as on Linux.
// Each poll runs pfctl six times, plus one per anchor (or wildcard
// listing) checkBypass reads before the guard's, at most maxEarlierReads
// more: none on a stock Mac.
const guardPoll = 10 * time.Second

// IPv6Guard is routetable's Guard on macOS: it keeps IPv6 from leaving
// around the tunnel (routetable.Exempt) with a pf anchor, GuardAnchor,
// under Apple's `anchor "com.apple/*"` (guardRules lists its rules), and
// the anchor's table, loaded together by one `pfctl -a
// com.apple/000.thinkpol -f - -o none`, pfctl's rule optimizer off so
// that pf holds the rules in the order written (load):
//
//	table <thinkpol_exempt6> persist { <Exempt.Direct's IPv6>, LinkScoped }
//
// and DNS to each IPv6 direct upstream (Exempt.Upstreams) on its port.
// An anchor nothing evaluates guards nothing: Apply first checks the main
// ruleset still has the hook (without it the guard fails, retried, and the
// health says ipv6_guard_not_enforced until the hook is there; /etc/pf.conf
// is never edited), and last, once the anchor is in place, that nothing
// lets IPv6 past it: a quick pass above the hook or in an anchor pf
// evaluates before it, an interface pf skips, an anchor under com.apple pf
// runs first (checkBypass: an ordinary failure, ipv6_guard_not_enforced,
// retried). pf is enabled by reference (`pfctl -E`), so the guard neither
// turns off a pf someone else enabled nor leaves pf on after it: the token
// goes to a record in the state directory first thing (by the pfctl's pid
// if its token can't be read, and then Apply fails until `pfctl -s
// References` names it), and Close releases it (`pfctl -X`), but only
// while that listing has it as taken by the pfctl the record names. States
// pf already holds would pass without a rule (pf's state policy is
// floating): after a load, an enable, or a failed Apply (a quick pass
// above the hook may have made some meanwhile), Apply kills the IPv6 ones
// whose other end isn't in the exempt table; while the same bypasses last,
// only once.
//
// The anchor and the reference stay when the process dies: a crash leaves
// IPv6 confined, as the route table's rejects do. The next start's
// routetable.Clear, under the route table's owner lock, closes a fresh
// guard, which flushes the anchor and releases a reference the record
// holds from this boot (one from an earlier boot went with it); a guard
// that applies instead takes the crashed run's reference over.
//
// Apply and Close change pf, and only the route table's Enforcer calls
// them, holding its owner lock; Watch only reads.
type IPv6Guard struct {
	mu     sync.Mutex
	pf     pfctl
	tokens tokenStore
	poll   time.Duration
	// own lists the host's addresses, to tell a state's local end.
	own func() ([]netip.Addr, error)

	// applied is what the last good load put in place, nil until then
	// and after a failed one.
	applied *appliedGuard
	// token is the reference this guard holds (nil: none); a zero value
	// is one whose token `pfctl -E` didn't print readably, known by its
	// pid only. recorded says the record has it as it is.
	token    *pfToken
	recorded bool
	// killStates: pf's states still need checking against applied (after
	// a load, an enable, or a failed Apply).
	killStates bool
	// killedUnder: what checkBypass read and found when the states were
	// last killed; valid while every Apply's check since has read and
	// found the same (false: never killed, statesStale, or a check that
	// saw otherwise or couldn't read pf). While valid, they aren't killed
	// again.
	killedUnder struct {
		seen  bypasses
		valid bool
	}
	// failing: the last Apply failed (but for unsupported); Watch says so.
	failing bool
	closed  bool
}

// appliedGuard is a guard Apply put in place: for exempt, the table it
// loaded, and the anchor's rules as pfctl listed them after the load.
type appliedGuard struct {
	exempt routetable.Exempt
	table  []netip.Prefix
	rules  []string
}

// exempts reports whether the guard lets anything out to addr: it is in
// the exempt table. An upstream's address isn't: only DNS to it is, and a
// state names hosts, not ports.
func (a *appliedGuard) exempts(addr netip.Addr) bool {
	for _, p := range a.table {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var _ routetable.Guard = (*IPv6Guard)(nil)

// errClosed: the guard was closed.
var errClosed = errors.New("firewall: the IPv6 guard is closed")

// NewIPv6Guard returns the host's guard, its record in netcfg.StateDir.
// Nothing is in place until Apply; Close removes what is there, a crashed
// run's anchor and reference included.
func NewIPv6Guard() *IPv6Guard {
	return newIPv6Guard(execPfctl{path: pfctlPath, timeout: pfctlTimeout}, tokenStore{dir: netcfg.StateDir, boot: trusteddir.BootSession}, guardPoll, hostAddrs)
}

func newIPv6Guard(pf pfctl, tokens tokenStore, poll time.Duration, own func() ([]netip.Addr, error)) *IPv6Guard {
	return &IPv6Guard{pf: pf, tokens: tokens, poll: poll, own: own}
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

// Apply puts e in place: the anchor (rules and tables in one load), then pf
// enabled by a reference of its own, then whatever lets IPv6 past the anchor
// checked (checkBypass), then states the anchor would have refused killed.
// Applying what is in place again only reads it back (the hook and what
// bypasses it, the rules exactly as listed after the load, every table
// entry, pf enabled) and reloads if the anchor or pf differ. A failed load
// leaves what was there (a pf transaction), a guard at least as strict as
// either. A load pf took but load refuses on reading it back stays,
// unverified, and the Apply fails and is retried. pf enforces it whenever pf
// is on (on the guard's reference after an earlier good load, or on another
// enabler's); the guard takes no reference for it. Flushing it would leave
// an empty anchor, which passes all IPv6. The package doc (macOS: loading
// and checking) has the reasoning: why it is never wider than the rules
// written but for what someone changed in the anchor between the load and
// the read-back (or a pfctl that optimized it anyway), and why the last
// verified guard isn't reloaded instead.
func (g *IPv6Guard) Apply(ctx context.Context, e routetable.Exempt) (err error) {
	if !validInterface.MatchString(e.TUN) {
		return fmt.Errorf("firewall: TUN %q isn't an interface name", e.TUN)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errClosed
	}
	if g.failing {
		// Whatever failed (a quick pass above the hook, pf on without the
		// anchor) may have let states be made that the anchor would
		// refuse.
		g.killStates = true
	}
	defer func() { g.failing = err != nil && !errors.Is(err, routetable.ErrGuardUnsupported) }()
	main, err := g.checkHook(ctx)
	if err != nil {
		// pf may evaluate no hook meanwhile: what got past the anchor is
		// unknown.
		g.statesStale()
		return err
	}
	if a := g.applied; a == nil || !a.exempt.Equal(e) || !g.intact(ctx, a) {
		g.applied = nil
		a, err := g.load(ctx, e)
		if err != nil {
			return err
		}
		g.applied = a
		g.statesStale()
	}
	// What doesn't stop enforcing is told at the end (later): a failed
	// release of a reference held before (oldRelease).
	var later []error
	// After the load, so pf comes on with the guard in place; a failure
	// here leaves the anchor applied, and the retry only enables.
	oldRelease, err := g.enable(ctx)
	later = append(later, oldRelease)
	if err == nil {
		// Last, so the interfaces pf does filter are guarded while
		// something lets IPv6 past the rest.
		b := g.checkBypass(ctx, main, e.TUN)
		if err = g.killIfDue(ctx, b); err == nil {
			err = b.asError()
		}
	}
	return errors.Join(append([]error{err}, later...)...)
}

// statesStale says pf's states need checking against the anchor, and
// that under which bypasses they were last killed no longer holds: after
// a load, an enable, or pf evaluating without the hook.
func (g *IPv6Guard) statesStale() {
	g.killStates, g.killedUnder.valid = true, false
}

// killIfDue kills the states the anchor would refuse (kill) when they
// need checking (killStates), unless every check since they were last
// killed saw the same bypasses: what a bypass lets through needs no
// state, and the anchor lets nothing else make one, so the retries while
// it lasts don't kill again. Any change to what checkBypass read up to
// the hook, or to what it found, kills (a bypass gone takes what it let be
// made), even one seen by an Apply that didn't kill, and so does a check
// that couldn't read pf: it can't tell they are the same.
func (g *IPv6Guard) killIfDue(ctx context.Context, b bypasses) error {
	if b.err != nil || !b.same(g.killedUnder.seen) {
		g.killedUnder.valid = false
	}
	if !g.killStates || g.killedUnder.valid {
		return nil
	}
	if err := g.kill(ctx, g.applied); err != nil {
		return err
	}
	g.killStates = false
	g.killedUnder.seen, g.killedUnder.valid = b, b.err == nil
	return nil
}

// checkHook reads pf's main ruleset (`pfctl -s rules`) and fails with an
// ordinary error, retried, when it doesn't evaluate the anchors under
// com.apple: the system may not have loaded /etc/pf.conf yet (an agent
// started at boot), or someone replaced it and may put the hook back.
func (g *IPv6Guard) checkHook(ctx context.Context) ([]byte, error) {
	out, err := g.pf.run(ctx, nil, "-s", "rules")
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

// bypass is one way past the guard's anchor: what the guard's error says
// of it (why), and, for a rule, where it is: the ruleset, the anchor
// calls that lead to it, and the rule as pfctl lists it (at).
type bypass struct {
	why, at string
}

// bypasses is what checkBypass found: every way past the anchor, in the
// order pf meets them, and every rule it read on the way (each where it
// is, as bypass.at), or, when pf couldn't be read, err alone.
type bypasses struct {
	found []bypass
	read  []string
	err   error
}

// same says b and o found the same bypasses reading the same rules.
func (b bypasses) same(o bypasses) bool {
	return slices.Equal(b.found, o.found) && slices.Equal(b.read, o.read)
}

// asError is the guard's error for b: nil when nothing lets IPv6 past the
// anchor, an ordinary failure naming each kind of way once otherwise.
func (b bypasses) asError() error {
	if b.err != nil {
		return b.err
	}
	var why []string
	for _, f := range b.found {
		if !slices.Contains(why, f.why) {
			why = append(why, f.why)
		}
	}
	if len(why) == 0 {
		return nil
	}
	return errors.New("firewall: " + strings.Join(why, "; "))
}

// checkBypass finds every way pf, evaluating the hook, lets outgoing IPv6
// past the anchor (an ordinary failure, the guard not enforced): a pass
// that ends evaluation (endsEvaluation) above the hook, in the main
// ruleset or in an anchor it calls there; an interface but lo0 and tun
// skipped (`set skip on`); an anchor under com.apple that sorts before
// the guard's. Such an anchor is a bypass by its existence (TP-126's
// decision): its rules are read only so that a change to them kills
// states (killIfDue). The anchors are read (anchorWalk) only when main or
// com.apple has one before the guard's.
func (g *IPv6Guard) checkBypass(ctx context.Context, main []byte, tun string) bypasses {
	w := &anchorWalk{pf: g.pf, seen: map[anchorWalkKey]bool{}}
	if err := w.ruleset(ctx, "", "", lines(main), false); err != nil {
		return bypasses{err: err}
	}
	b, err := g.readBypass(ctx)
	if err != nil {
		return bypasses{err: err}
	}
	if s := slices.DeleteFunc(b.skipped, func(n string) bool { return n == "lo0" || n == tun }); len(s) > 0 {
		w.found = append(w.found, bypass{why: fmt.Sprintf("pf skips %s (`set skip on`), so the IPv6 guard never sees its packets", strings.Join(s, ", "))})
	}
	if len(b.before) > 0 {
		w.found = append(w.found, bypass{why: fmt.Sprintf("pf evaluates %s before the IPv6 guard's anchor: a quick pass there lets IPv6 past it", strings.Join(b.before, ", "))})
		if err := w.listed(ctx, appleAnchor+"/*", b.before, false); err != nil {
			return bypasses{err: err}
		}
	}
	return bypasses{found: w.found, read: w.read}
}

// maxEarlierReads bounds the pfctl runs one check spends on what pf
// evaluates before the guard's anchor: each anchor's rules and each
// wildcard's listing.
const maxEarlierReads = 16

// anchorWalk reads the rulesets pf evaluates before the guard's anchor,
// the main ruleset's down to the hook and every anchor they call, in
// pf's order, for passes that end evaluation (endsEvaluation): each is a
// bypass, as is an anchor it can't read, and more to read than
// maxEarlierReads pfctl runs. It keeps every rule it read (read), where
// each is, for the kill's identity.
type anchorWalk struct {
	pf    pfctl
	runs  int
	seen  map[anchorWalkKey]bool
	found []bypass
	read  []string
}

type anchorWalkKey struct {
	anchorCall
	quick bool
}

// ruleset reads ls, the rules of the ruleset at base ("" for the main
// ruleset, read down to the hook), which the anchor calls via led to,
// inside quick anchors if inQuick.
func (w *anchorWalk) ruleset(ctx context.Context, via, base string, ls []string, inQuick bool) error {
	// name: the ruleset, as the error says it; where: how pf got to it.
	name, where := "pf's main ruleset", "pf's main ruleset"
	if base != "" {
		name, where = "anchor "+base, "anchor "+via
		if inQuick {
			where += " (in a quick anchor)"
		}
	}
	for _, l := range ls {
		f := strings.Fields(l)
		if base == "" && isHook(f) {
			return nil
		}
		at := where + ": " + l
		w.read = append(w.read, at)
		if endsEvaluation(f, inQuick) {
			why := fmt.Sprintf("a pass in %s, which pf evaluates before the IPv6 guard's, lets IPv6 past it", name)
			if base == "" {
				why = fmt.Sprintf("a `pass ... quick` rule above `anchor %s` in pf's main ruleset lets IPv6 past the guard", appleHook)
			}
			w.found = append(w.found, bypass{why: why, at: at})
			continue
		}
		called, rest, ok := anchorRule(l)
		if !ok || !reachesIPv6Out(rest, 0) {
			continue
		}
		c, ok := resolveAnchor(base, called)
		if !ok {
			w.found = append(w.found, bypass{
				why: fmt.Sprintf("%s calls an anchor the IPv6 guard can't name, before its own: a pass there could let IPv6 past it", name),
				at:  at,
			})
			continue
		}
		if err := w.call(ctx, via, c, inQuick || slices.Contains(rest, "quick")); err != nil {
			return err
		}
	}
	return nil
}

// call reads the anchor c leads to, or each of its children (listed).
// via: the calls that led to the rule; quick: inside a quick anchor.
func (w *anchorWalk) call(ctx context.Context, via string, c anchorCall, quick bool) error {
	if !c.wildcard {
		return w.anchor(ctx, via, c.path, quick, false)
	}
	if !w.markRead(c, quick) || !w.spend() {
		return nil
	}
	out, err := w.pf.run(ctx, nil, "-a", c.path, "-s", "Anchors")
	children, err := childAnchors(c.path, out, err)
	if err != nil {
		return err
	}
	return w.listed(ctx, chain(via, c.path+"/*"), children, quick)
}

// listed reads each anchor a listing named, in order, up to the guard's
// own: every outgoing IPv6 packet that reaches the guard's anchor ends
// there, so the ones after it are never reached that way.
func (w *anchorWalk) listed(ctx context.Context, via string, paths []string, quick bool) error {
	for _, p := range paths {
		if p == GuardAnchor {
			break
		}
		if err := w.anchor(ctx, via, p, quick, true); err != nil {
			return err
		}
	}
	return nil
}

// anchor reads the anchor at path, called via the calls named, and what
// it calls. One that doesn't exist holds nothing when a rule names it
// (pf calls an empty one), but a listing named it, so one that reads as
// missing is one the guard reads by another name than pf's: a bypass. A
// path the guard can't read (nameable) is a bypass too. What was read
// already (with quick alike) isn't read again: it holds what it held.
func (w *anchorWalk) anchor(ctx context.Context, via, path string, quick, listed bool) error {
	if path == GuardAnchor {
		return nil
	}
	via = chain(via, path)
	if !nameable(path) {
		w.found = append(w.found, bypass{why: fmt.Sprintf("pf evaluates an anchor the IPv6 guard can't read, %q, before its own: a pass there could let IPv6 past it", path), at: "anchor " + via})
		return nil
	}
	if !w.markRead(anchorCall{path: path}, quick) || !w.spend() {
		return nil
	}
	b, exists, err := rulesOf(ctx, w.pf, path, false)
	if err != nil {
		return err
	}
	if !exists && listed {
		w.found = append(w.found, bypass{why: fmt.Sprintf("pf lists anchor %s, but it reads as missing: a pass there could let IPv6 past the IPv6 guard", path), at: "anchor " + via})
		return nil
	}
	ls, err := readLines(b)
	if err != nil {
		return err
	}
	return w.ruleset(ctx, via, path, ls, quick)
}

// chain is the anchor calls via, then name.
func chain(via, name string) string {
	if via == "" {
		return name
	}
	return via + " > " + name
}

// markRead says c, read with quick, hasn't been read yet, and marks it
// read.
func (w *anchorWalk) markRead(c anchorCall, quick bool) bool {
	k := anchorWalkKey{c, quick}
	if w.seen[k] {
		return false
	}
	w.seen[k] = true
	return true
}

// spend counts one more pfctl run; past maxEarlierReads it says so, once,
// as a bypass, and refuses.
func (w *anchorWalk) spend() bool {
	w.runs++
	if w.runs == maxEarlierReads+1 {
		w.found = append(w.found, bypass{why: fmt.Sprintf("the IPv6 guard reads at most %d pfctl listings of what pf evaluates before its anchor, and there is more: a pass there could let IPv6 past it", maxEarlierReads)})
	}
	return w.runs <= maxEarlierReads
}

// bypassListing is what pf lists of the ways past the anchor but the
// main ruleset: every name it skips, and the anchors under com.apple that
// sort before the guard's.
type bypassListing struct {
	skipped, before []string
}

// readBypass reads them, for checkBypass and for diagnostics. A listing
// pf refuses, or one the guard can't read, is a failure. com.apple
// missing (answerNoAnchors) lists none: the guard's anchor, under it, is
// missing too, which Apply's load and the poll's intact see.
func (g *IPv6Guard) readBypass(ctx context.Context) (bypassListing, error) {
	ifcs, err := g.pf.run(ctx, nil, "-s", "Interfaces", "-v")
	if err != nil {
		return bypassListing{}, err
	}
	skips, err := skippedNames(ifcs.stdout)
	if err != nil {
		return bypassListing{}, err
	}
	anchors, err := g.pf.run(ctx, nil, "-a", appleAnchor, "-s", "Anchors")
	before, err := anchorsBefore(anchors, err)
	if err != nil {
		return bypassListing{}, err
	}
	return bypassListing{skipped: skips, before: before}, nil
}

// load loads e's anchor and reads it back. The load runs with pfctl's
// rule optimizer off (`-o none`): the default, `basic`, re-orders rules
// (and may merge them into a table), and saneRules expects the listing
// in the order and shape the guard wrote.
func (g *IPv6Guard) load(ctx context.Context, e routetable.Exempt) (*appliedGuard, error) {
	table, upstreams := exemptPrefixes(e), upstreamTargets(e)
	if _, err := g.pf.run(ctx, []byte(anchorText(e.TUN, table, upstreams)), "-a", GuardAnchor, "-f", "-", "-o", "none"); err != nil {
		return nil, fmt.Errorf("firewall: load the IPv6 guard: %w", err)
	}
	rules, err := g.listRules(ctx)
	if err != nil {
		return nil, err
	}
	if err := saneRules(rules, e.TUN, upstreams); err != nil {
		return nil, err
	}
	got, err := g.listTable(ctx, exemptTable)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(got, table) {
		return nil, fmt.Errorf("firewall: pf's table %s holds %d entries unlike the %d loaded", exemptTable, len(got), len(table))
	}
	return &appliedGuard{exempt: e, table: table, rules: rules}, nil
}

// listRules lists the guard's anchor's rules; an anchor that doesn't
// exist has none (AnchorMissing), and any other failure is an error.
func (g *IPv6Guard) listRules(ctx context.Context) ([]string, error) {
	b, _, err := rulesOf(ctx, g.pf, GuardAnchor, false)
	if err != nil {
		return nil, err
	}
	return readLines(b)
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
var errNoTable = errors.New("firewall: the guard's table doesn't exist")

func (g *IPv6Guard) listTable(ctx context.Context, name string) ([]netip.Prefix, error) {
	out, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-t", name, "-T", "show")
	if err != nil {
		if noTable(out.stderr) {
			return nil, fmt.Errorf("%w: %w", errNoTable, err)
		}
		return nil, err
	}
	return parseTable(out.stdout)
}

// intact reports whether the anchor still holds exactly a: its rules as
// listed after the load, line for line, and the table, entry for entry
// (an entry added is a leak, one removed a refusal).
func (g *IPv6Guard) intact(ctx context.Context, a *appliedGuard) bool {
	rules, err := g.listRules(ctx)
	if err != nil || !slices.Equal(rules, a.rules) {
		return false
	}
	table, err := g.listTable(ctx, exemptTable)
	return err == nil && slices.Equal(table, a.table)
}

func (g *IPv6Guard) enabled(ctx context.Context) (bool, error) {
	out, err := g.pf.run(ctx, nil, "-s", "info")
	if err != nil {
		return false, err
	}
	return parseEnabled(out.stdout)
}

// references reads `pfctl -s References` (parseReferences).
func (g *IPv6Guard) references(ctx context.Context) ([]pfReference, bool, error) {
	out, err := g.pf.run(ctx, nil, "-s", "References")
	if err != nil {
		return nil, false, fmt.Errorf("firewall: pf's references: %w", err)
	}
	refs, understood := parseReferences(out)
	return refs, understood, nil
}

// errUnreadToken: pfctl -E took a reference whose token neither its
// output nor pf's listing gives; it is recorded by pid, and Apply and
// Close fail until the token is known or the reference is gone.
var errUnreadToken = errors.New("firewall: pf's enable token is unknown")

// resolve finds the token of t, a reference known by its pid only: the
// token pf lists for that pid. ok false with a nil error: pf's listing,
// readable, has no reference of that pid any more.
func (g *IPv6Guard) resolve(ctx context.Context, t pfToken) (uint64, bool, error) {
	refs, understood, err := g.references(ctx)
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

// errUnreadReferences: `pfctl -s References` printed a listing the guard
// can't read, in which a reference's absence proves nothing.
var errUnreadReferences = errors.New("firewall: pf's references listed in a form the guard can't read")

// enable makes sure pf is on with a reference of the guard's, and the
// record names it: kept while pf is on; taken over from the record (a
// crashed run's, this boot); taken anew when the guard has none, or when
// pf is off (someone ran `pfctl -d`), the old one then released if pf
// still lists it. oldRelease is that release's failure, which leaves pf
// on and the guard's reference recorded: the caller goes on enforcing
// and tells it after.
func (g *IPv6Guard) enable(ctx context.Context) (oldRelease, err error) {
	on, err := g.enabled(ctx)
	if err != nil {
		return nil, err
	}
	if err := g.adoptRecord(); err != nil {
		return nil, err
	}
	if err := g.resolveToken(ctx); err != nil {
		return nil, err
	}
	if on && g.token != nil {
		return nil, g.recordToken()
	}
	// pf was off, or on by someone else's reference: states it holds from
	// then need checking.
	g.statesStale()
	return g.takeReference(ctx)
}

// adoptRecord takes over the reference the record names (a crashed
// run's, this boot) when the guard holds none, and removes a stale record.
func (g *IPv6Guard) adoptRecord() error {
	if g.token != nil {
		return nil
	}
	t, state, err := g.tokens.read()
	switch {
	case err != nil:
		return err
	case state == recordHeld:
		g.token, g.recorded = &t, true
	case state == recordStale:
		return g.tokens.remove()
	}
	return nil
}

// resolveToken finds the token of a reference the guard knows by its pid
// only; one pf no longer lists is dropped, and its record replaced by the
// next reference's.
func (g *IPv6Guard) resolveToken(ctx context.Context) error {
	if g.token == nil || g.token.value != 0 {
		return nil
	}
	t, err := g.resolvedToken(ctx, g.token)
	if err != nil {
		return err
	}
	g.token, g.recorded = t, false
	return nil
}

// resolvedToken is t with its token found when t is known by its pid
// only; nil when pf no longer lists that pid's reference (or t is nil).
func (g *IPv6Guard) resolvedToken(ctx context.Context, t *pfToken) (*pfToken, error) {
	if t == nil || t.value != 0 {
		return t, nil
	}
	v, ok, err := g.resolve(ctx, *t)
	if err != nil || !ok {
		return nil, err
	}
	return &pfToken{value: v, pid: t.pid}, nil
}

// recordToken writes the guard's reference to the record, unless it is
// there already.
func (g *IPv6Guard) recordToken() error {
	if g.recorded {
		return nil
	}
	if err := g.tokens.write(*g.token); err != nil {
		return err
	}
	g.recorded = true
	return nil
}

// takeReference turns pf on with a new reference (`pfctl -E`) and
// records it, then releases the one the guard held, if pf still lists it:
// that release's failure is oldRelease, apart from err.
func (g *IPv6Guard) takeReference(ctx context.Context) (oldRelease, err error) {
	old := g.token
	out, err := g.pf.run(ctx, nil, "-E")
	if err != nil {
		return nil, fmt.Errorf("firewall: enable pf: %w", err)
	}
	t := pfToken{pid: out.pid}
	v, perr := parseToken(out)
	if perr == nil {
		t.value = v
	} else if v, ok, _ := g.resolve(ctx, t); ok {
		t.value = v
	}
	g.token, g.recorded = &t, false
	if err := g.recordToken(); err != nil {
		return nil, err
	}
	if old != nil {
		// pf was off although the guard held a reference. If pfctl -d
		// left it listed, release it now that pf is on again (pf refuses
		// -X while off); best effort: the new one is the record's, and
		// enforcing goes on first. A release that fails (a References
		// listing it can't read) is told after, not dropped: the record
		// now names the new reference only.
		if err := g.release(ctx, *old); err != nil {
			oldRelease = fmt.Errorf("firewall: pf enabled anew, but releasing the reference it held before failed (pid %d): %w", old.pid, err)
		}
	}
	if t.value == 0 {
		return oldRelease, fmt.Errorf("%w (pfctl pid %d): %w", errUnreadToken, t.pid, perr)
	}
	return oldRelease, nil
}

// release lets go of t, a reference with a known token: `pfctl -X` if pf
// lists it as taken by the pfctl the guard recorded, nothing if it isn't
// listed (gone already) or is someone else's (the value was reused).
func (g *IPv6Guard) release(ctx context.Context, t pfToken) error {
	refs, understood, err := g.references(ctx)
	if err != nil {
		return err
	}
	if !understood {
		// Not listed in a listing the guard can't read proves nothing:
		// fail, so Close keeps the record and a later one retries.
		return errUnreadReferences
	}
	if referenced(refs, t) != refOurs {
		return nil
	}
	if _, err := g.pf.run(ctx, nil, "-X", fmt.Sprint(t.value)); err != nil {
		return fmt.Errorf("firewall: release pf's reference: %w", err)
	}
	return nil
}

// kill kills the IPv6 states pf holds to or from an address outside a's
// exempt table: they would pass without the anchor. A direct upstream's
// address is outside it (only DNS to it is exempt, and `-k` names hosts,
// not ports): its states go too, and DNS goes on through its stateless
// rule. A state is named by its
// two ends, the host's own address and the other one (`pfctl -k local -k
// remote` for one the host opened, `-k remote -k local` for one opened to
// it); exempt ones and IPv4 ones are left alone. Killing a tunnelled
// connection's state is harmless: the anchor passes it statelessly.
func (g *IPv6Guard) kill(ctx context.Context, a *appliedGuard) error {
	out, err := g.pf.run(ctx, nil, "-s", "states")
	if err != nil {
		return fmt.Errorf("firewall: pf's states: %w", err)
	}
	states, err := parseStateAddrs(out.stdout)
	if err != nil {
		return fmt.Errorf("firewall: pf's states: %w", err)
	}
	if len(states) == 0 {
		return nil
	}
	own, err := g.own()
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
				if !r.IsLoopback() && !a.exempts(r) {
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
			if _, err := g.pf.run(ctx, nil, args...); err != nil {
				return fmt.Errorf("firewall: kill pf's states the guard refuses: %w", err)
			}
		}
	}
	return nil
}

// flush empties the anchor: its rules, then its tables (`-F all` would
// also flush pf's global state table and statistics). Whatever each -F
// answered, succeeded or failed (what pfctl answers for an anchor that
// doesn't exist is unrecorded), the anchor's listing after it decides:
// no rule listed (an anchor that doesn't exist lists none, AnchorMissing),
// then no guard table (noTable), is empty; anything else, a listing that
// fails included, fails it with the -F's error and the listing's.
func (g *IPv6Guard) flush(ctx context.Context) error {
	for _, step := range []struct {
		modifier string
		empty    func(context.Context) error
	}{{"rules", g.noRules}, {"Tables", g.noGuardTable}} {
		_, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-F", step.modifier)
		if errors.Is(err, routetable.ErrGuardUnsupported) {
			return err
		}
		if lerr := step.empty(ctx); lerr != nil {
			return fmt.Errorf("firewall: remove the IPv6 guard: %w", errors.Join(err, lerr))
		}
	}
	return nil
}

// noRules is nil if the guard's anchor lists no rule.
func (g *IPv6Guard) noRules(ctx context.Context) error {
	rules, err := g.listRules(ctx)
	if err == nil && len(rules) > 0 {
		err = fmt.Errorf("firewall: pf still lists %d rules in the guard's anchor", len(rules))
	}
	return err
}

// noGuardTable is nil if pf answers that the guard's table doesn't exist.
func (g *IPv6Guard) noGuardTable(ctx context.Context) error {
	_, err := g.listTable(ctx, exemptTable)
	switch {
	case errors.Is(err, errNoTable):
		return nil
	case err == nil:
		return fmt.Errorf("firewall: pf still holds the guard's table %s", exemptTable)
	}
	return err
}

// Close flushes the anchor's rules and table, then releases the
// reference the guard holds, or the one its record holds from this boot
// (a fresh guard's Close is how a crashed run's guard goes), and removes
// the record. A failure, a reference whose token can't be found included,
// leaves the guard and its record in place for the next run's
// routetable.Clear, under the route table's owner lock; the anchor goes
// before the reference, so pf is never left off with the anchor still
// meant to be in place. With no pfctl at all there is nothing to remove.
func (g *IPv6Guard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	ctx := context.Background()
	g.applied = nil
	err := g.flush(ctx)
	if errors.Is(err, routetable.ErrGuardUnsupported) {
		return g.forget()
	}
	if err != nil {
		return err
	}
	t := g.token
	if t == nil {
		rec, state, err := g.tokens.read()
		if err != nil {
			return err
		}
		if state == recordHeld {
			t = &rec
		}
	}
	t, err = g.resolvedToken(ctx, t)
	if err != nil {
		return err
	}
	if t != nil {
		if err := g.release(ctx, *t); err != nil {
			return err
		}
	}
	return g.forget()
}

// forget removes the record and closes the guard.
func (g *IPv6Guard) forget() error {
	if err := g.tokens.remove(); err != nil {
		return err
	}
	g.token, g.recorded, g.closed = nil, false, true
	return nil
}

// Watch polls the guard every guardPoll and signals, coalesced, when it
// isn't whole any more: the last Apply failed (so a retry is due even
// without the Enforcer's own), or, applied, the hook is gone or bypassed
// (checkBypass included), pf is off, the anchor's rules or table changed.
// pf has no event stream. The channel closes when ctx ends.
func (g *IPv6Guard) Watch(ctx context.Context) (<-chan struct{}, error) {
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		return nil, errClosed
	}
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		t := time.NewTicker(g.poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if g.broken(ctx) {
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out, nil
}

// broken reports whether the guard isn't whole now; reading it back
// failing counts as not whole.
func (g *IPv6Guard) broken(ctx context.Context) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || ctx.Err() != nil {
		return false
	}
	if g.failing {
		return true
	}
	if g.applied == nil {
		return false
	}
	main, err := g.checkHook(ctx)
	if err != nil {
		return true
	}
	if b := g.checkBypass(ctx, main, g.applied.exempt.TUN); b.err != nil || len(b.found) > 0 || !g.intact(ctx, g.applied) {
		return true
	}
	on, err := g.enabled(ctx)
	return err != nil || !on
}
