package firewall

import (
	"context"
	"errors"
	"fmt"
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
// if its token can't be read, and then Apply, enforcing first while pf is
// on, fails until `pfctl -s References` names it or no longer lists its
// pid), and Close releases it
// (`pfctl -X`), but only while that listing has it as taken by the pfctl
// the record names. States pf already holds would pass without a rule
// (pf's state policy is floating): after a load, an enable, pf seen off,
// or a failed Apply (a quick pass above the hook may have made some
// meanwhile), Apply kills the IPv6 ones whose other end isn't in the
// exempt table; while the same bypasses last, only once.
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
	mu   sync.Mutex
	poll time.Duration
	// pfEnabler holds pf on by the guard's reference (pf, its record).
	pfEnabler
	// own lists the host's addresses, to tell a state's local end.
	own func() ([]netip.Addr, error)

	// applied is what the last good load put in place, nil until then
	// and after a failed one.
	applied *appliedGuard
	// killStates: pf's states still need checking against applied
	// (statesStale, or a failed Apply).
	killStates bool
	// killedUnder: what checkBypass read and found when the states were
	// last killed; valid while every check since, an Apply's or the
	// poll's, has read and found the same (false: never killed,
	// statesStale, or a check that saw otherwise or couldn't read pf).
	// While valid, they aren't killed again.
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
	g := &IPv6Guard{poll: poll, own: own, pfEnabler: pfEnabler{pf: pf, tokens: tokens}}
	g.stale = g.statesStale
	return g
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
	defer func() { err = guardUnsupported(err) }() // runs first
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
	// After the load, so pf comes on with the guard in place; a failure
	// here leaves the anchor applied, and the retry only enables. after
	// (a failed release of an older reference, an unread token with pf
	// on) doesn't stop enforcing: it is told at the end.
	after, err := g.enable(ctx)
	if err == nil {
		// Last, so the interfaces pf does filter are guarded while
		// something lets IPv6 past the rest.
		b := g.checkBypass(ctx, main, e.TUN)
		err = errors.Join(g.killIfDue(ctx, b), b.asError())
	}
	return errors.Join(err, after)
}

// statesStale says pf's states need checking against the anchor, and
// that under which bypasses they were last killed no longer holds: after
// a load, an enable, pf seen off, pf evaluating without the hook, or a
// check that saw the bypasses change (sawBypasses).
func (g *IPv6Guard) statesStale() {
	g.killStates, g.killedUnder.valid = true, false
}

// sawBypasses records what a check saw: one that couldn't read pf, or saw
// otherwise than the states were last killed under, leaves them stale.
// An Apply's check and the poll's both report here, so a change the poll
// saw kills at the next Apply even if it is gone by then.
func (g *IPv6Guard) sawBypasses(b bypasses) {
	if b.err != nil || !b.same(g.killedUnder.seen) {
		g.statesStale()
	}
}

// killIfDue kills the states the anchor would refuse (kill) when they
// need checking (killStates), unless every check since they were last
// killed saw the same bypasses (sawBypasses): what a bypass lets through
// needs no state, and the anchor lets nothing else make one, so the
// retries while it lasts don't kill again. Any change to the rules'
// text checkBypass read up to the hook, or to what it found, kills (a
// bypass gone takes what it let be made), even one seen by an Apply that
// didn't kill or by a poll, and so does a check that couldn't read pf:
// it can't tell they are the same.
func (g *IPv6Guard) killIfDue(ctx context.Context, b bypasses) error {
	g.sawBypasses(b)
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
func (g *IPv6Guard) checkHook(ctx context.Context) ([]byte, error) { return checkHook(ctx, g.pf) }

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
// decision); its rules are walked as well, which adds what they hold to
// the findings and to the kill's identity (killIfDue). The anchors are
// read (anchorWalk) only when main or com.apple has one before the guard's.
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
// there, so the ones after it are never reached that way. pf's names are
// unique, so a name listed twice is one whose newline broke the
// listing's layout (`a\n` lists as `a` and a blank line, right after a
// real `a`): a name the guard can't read, so a bypass, not a listing
// error, which would fail every retry the same way.
func (w *anchorWalk) listed(ctx context.Context, via string, paths []string, quick bool) error {
	for i, p := range paths {
		if p == GuardAnchor {
			break
		}
		if slices.Contains(paths[:i], p) {
			w.found = append(w.found, bypass{why: fmt.Sprintf("pf lists anchor %s twice, so another anchor's name holds a newline the IPv6 guard can't read: a pass there could let IPv6 past it", p), at: "anchor " + chain(via, p)})
			continue
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
		w.found = append(w.found, bypass{why: fmt.Sprintf("the IPv6 guard spends at most %d pfctl runs on what pf evaluates before its anchor, and there is more: a pass there could let IPv6 past it", maxEarlierReads)})
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
	skips, err := SkippedNames(ifcs.stdout)
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

func (g *IPv6Guard) listTable(ctx context.Context, name string) ([]netip.Prefix, error) {
	return listTable(ctx, g.pf, GuardAnchor, name, false, "IPv6 guard")
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
	return killStates(ctx, g.pf, g.own, a.exempts, false, "the guard refuses")
}

// flush empties the anchor: its rules, then its tables (`-F all` would
// also flush pf's global state table and statistics). Whatever each -F
// answered, succeeded or failed (what pfctl answers for an anchor that
// doesn't exist is unrecorded), the anchor's listing after it decides:
// no rule listed (an anchor that doesn't exist lists none, AnchorMissing),
// then no guard table (noTable), is empty; anything else, a listing that
// fails included, fails it with the -F's error and the listing's.
func (g *IPv6Guard) flush(ctx context.Context) error {
	return flushAnchor(ctx, g.pf, GuardAnchor, false, "IPv6 guard", exemptTable)
}

// Close flushes the anchor's rules and table, then releases the
// references the guard still owes (a record write or a release failed
// after pf was enabled anew), then the one it holds, or the one its
// record holds from this boot (a fresh guard's Close is how a crashed
// run's guard goes), and removes the record. The owed go first: pf stays
// on by the guard's own reference while they are released (pf refuses
// -X while off). A failure, a reference whose token can't be found
// included, leaves the guard and its record in place for the next run's
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
	if errors.Is(err, errNoPfctl) {
		return g.forget()
	}
	if err != nil {
		return guardUnsupported(err)
	}
	if err := g.releaseAll(ctx); err != nil {
		return guardUnsupported(err)
	}
	g.closed = true
	return nil
}

// guardUnsupported is err, wrapping routetable.ErrGuardUnsupported too
// when there is no pfctl (errNoPfctl).
func guardUnsupported(err error) error {
	if errors.Is(err, errNoPfctl) && !errors.Is(err, routetable.ErrGuardUnsupported) {
		return fmt.Errorf("%w: %w", routetable.ErrGuardUnsupported, err)
	}
	return err
}

// forget removes the record and closes the guard.
func (g *IPv6Guard) forget() error {
	if err := g.pfEnabler.forget(); err != nil {
		return err
	}
	g.closed = true
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
// failing counts as not whole. It reads pf's status first, failing or
// not: pf passes anything while off, and someone else may turn it back
// on before the next Apply reads it (a persistent bypass keeps the guard
// failing, its states killed under that bypass), so pf seen off marks
// the states stale.
func (g *IPv6Guard) broken(ctx context.Context) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || ctx.Err() != nil || (g.applied == nil && !g.failing) {
		return false
	}
	on, onErr := g.enabled(ctx)
	if onErr == nil && !on {
		g.statesStale()
	}
	if g.failing || (onErr == nil && !on) {
		return true
	}
	main, err := g.checkHook(ctx)
	if err != nil {
		g.statesStale() // pf may run no hook meanwhile
		return true
	}
	b := g.checkBypass(ctx, main, g.applied.exempt.TUN)
	g.sawBypasses(b)
	return onErr != nil || b.err != nil || len(b.found) > 0 || !g.intact(ctx, g.applied)
}
