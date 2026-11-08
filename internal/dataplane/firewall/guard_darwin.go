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

// checkHook is IPv6Guard.checkHook over pf, the kill switch's too.
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
	return listTable(ctx, g.pf, GuardAnchor, name, false)
}

// listTable lists table name of anchor (parseTableOf: both families, or
// IPv6 only); errNoTable when pf answers it doesn't exist.
func listTable(ctx context.Context, pf pfctl, anchor, name string, both bool) ([]netip.Prefix, error) {
	out, err := pf.run(ctx, nil, "-a", anchor, "-t", name, "-T", "show")
	if err != nil {
		if noTable(out.stderr) {
			return nil, fmt.Errorf("%w: %w", errNoTable, err)
		}
		return nil, err
	}
	return parseTableOf(out.stdout, both)
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

// errUnreadReferences: `pfctl -s References` printed a listing the guard
// can't read, in which a reference's absence proves nothing.
var errUnreadReferences = errors.New("firewall: pf's references listed in a form the guard can't read")

// enable makes sure pf is on with a reference of the guard's, and the
// record names it: kept while pf is on; taken over from the record (a
// crashed run's, this boot); taken anew when the guard has none, or when
// pf is off (someone ran `pfctl -d`), the old one then released if pf
// still lists it. after is what leaves pf on and the guard's reference
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
	// pf off (marked above), or on without a reference of the guard's
	// (someone else's, or a plain `pfctl -e`): states it holds from then
	// need checking.
	pe.stale()
	return pe.takeReference(ctx)
}

// adoptRecord takes over the reference the record names (a crashed
// run's, this boot) when the guard holds none and doesn't owe it, and
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
		// A failed write left the record naming a reference this guard
		// replaced: owed, not held. The next write replaces the record.
		return nil
	case state == recordHeld:
		pe.token, pe.recorded = &t, true
	case state == recordStale:
		return pe.tokens.remove()
	}
	return nil
}

// resolveToken finds the token of a reference the guard knows by its pid
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

// recordToken writes the guard's reference to the record, unless it is
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
// records it, then releases the one the guard held, if pf still lists it
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

// releaseOwed releases the references the guard held before pf was
// enabled anew (owed), now that the record names the new one: pf was off
// although the guard held them. If pfctl -d left them listed, they go now
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
// lists it as taken by the pfctl the guard recorded, nothing if it isn't
// listed (gone already) or is someone else's (the value was reused).
func (pe *pfEnabler) release(ctx context.Context, t pfToken) error {
	refs, understood, err := pe.references(ctx)
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
	if _, err := pe.pf.run(ctx, nil, "-X", fmt.Sprint(t.value)); err != nil {
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
	return killStates(ctx, g.pf, g.own, a.exempts, false, "the guard refuses")
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

// flush empties the anchor: its rules, then its tables (`-F all` would
// also flush pf's global state table and statistics). Whatever each -F
// answered, succeeded or failed (what pfctl answers for an anchor that
// doesn't exist is unrecorded), the anchor's listing after it decides:
// no rule listed (an anchor that doesn't exist lists none, AnchorMissing),
// then no guard table (noTable), is empty; anything else, a listing that
// fails included, fails it with the -F's error and the listing's.
func (g *IPv6Guard) flush(ctx context.Context) error {
	return flushAnchor(ctx, g.pf, GuardAnchor, exemptTable, false, "IPv6 guard")
}

// flushAnchor is IPv6Guard.flush for anchor, its table table (of both
// families, or IPv6 only) and owner's name, for the error.
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
		_, err := listTable(ctx, pf, anchor, table, both)
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
		if errors.Is(err, routetable.ErrGuardUnsupported) {
			return err
		}
		if lerr := step.empty(ctx); lerr != nil {
			return fmt.Errorf("firewall: remove the %s: %w", owner, errors.Join(err, lerr))
		}
	}
	return nil
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
	if errors.Is(err, routetable.ErrGuardUnsupported) {
		return g.forget()
	}
	if err != nil {
		return err
	}
	if err := g.releaseAll(ctx); err != nil {
		return err
	}
	g.closed = true
	return nil
}

// forget removes the record and closes the guard.
func (g *IPv6Guard) forget() error {
	if err := g.pfEnabler.forget(); err != nil {
		return err
	}
	g.closed = true
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
