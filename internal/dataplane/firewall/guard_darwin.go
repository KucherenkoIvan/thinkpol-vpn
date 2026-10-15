package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// guardPoll is how often Watch reads the guard back from pf: pf has no
// event stream, so a flush, a disabled pf or a replaced main ruleset is
// seen within guardPoll (and a debounce) rather than at once as on Linux.
// Each poll runs pfctl five times.
const guardPoll = 10 * time.Second

// IPv6Guard is routetable's Guard on macOS: it keeps IPv6 from leaving
// around the tunnel (routetable.Exempt) with a pf anchor, GuardAnchor,
// under Apple's `anchor "com.apple/*"` (guardRules lists its rules), and
// the anchor's two tables, loaded together by one `pfctl -a
// com.apple/000.thinkpol -f -`:
//
//	table <thinkpol_exempt6> persist { <Exempt.Direct's IPv6>, LinkScoped }
//	table <thinkpol_upstream6> persist { <Exempt.Upstreams' IPv6> }
//
// An anchor nothing evaluates guards nothing: Apply first checks the main
// ruleset still has the hook (without it the guard is unsupported, and the
// health says ipv6_guard_unsupported; /etc/pf.conf is never edited), and
// that no quick pass above it ends evaluation first (an ordinary failure:
// ipv6_guard_not_enforced, retried). pf is enabled by reference (`pfctl
// -E`), so the guard neither turns off a pf someone else enabled nor
// leaves pf on after it: the token goes to a record in the state directory
// first thing (by the pfctl's pid if its token can't be read, and then
// Apply fails until `pfctl -s References` names it), and Close releases it
// (`pfctl -X`), but only while that listing has it as taken by the pfctl
// the record names. States pf already holds would pass without a rule
// (pf's state policy is floating): after a load or an enable, Apply kills
// the IPv6 ones to destinations the guard doesn't exempt.
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
	// a load or an enable).
	killStates bool
	// failing: the last Apply failed (but for unsupported); Watch says so.
	failing bool
	closed  bool
}

// appliedGuard is a guard Apply put in place: for exempt, the tables it
// loaded, and the anchor's rules as pfctl listed them after the load.
type appliedGuard struct {
	exempt          routetable.Exempt
	table, upstream []netip.Prefix
	rules           []string
}

// exempts reports whether a is a destination the guard lets out by
// address: in the exempt table or the upstream table.
func (a *appliedGuard) exempts(addr netip.Addr) bool {
	for _, p := range a.table {
		if p.Contains(addr) {
			return true
		}
	}
	for _, p := range a.upstream {
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
	return newIPv6Guard(execPfctl{path: pfctlPath, timeout: pfctlTimeout}, tokenStore{dir: netcfg.StateDir, boot: bootSession}, guardPoll, hostAddrs)
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

// Apply puts e in place: the anchor (rules and tables in one load), then
// pf enabled by a reference of its own, then states the anchor would have
// refused killed. Applying what is in place again only reads it back (the
// hook, the rules exactly as listed after the load, every table entry, pf
// enabled) and reloads if anything differs. A failed load leaves what was
// there (a pf transaction), a guard at least as strict as either.
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
	defer func() { g.failing = err != nil && !errors.Is(err, routetable.ErrGuardUnsupported) }()
	if err := g.checkHook(ctx); err != nil {
		return err
	}
	if a := g.applied; a == nil || !a.exempt.Equal(e) || !g.intact(ctx, a) {
		g.applied = nil
		a, err := g.load(ctx, e)
		if err != nil {
			return err
		}
		g.applied, g.killStates = a, true
	}
	// After the load, so pf comes on with the guard in place; a failure
	// here leaves the anchor applied, and the retry only enables.
	if err := g.enable(ctx); err != nil {
		return err
	}
	if g.killStates {
		if err := g.kill(ctx, g.applied); err != nil {
			return err
		}
		g.killStates = false
	}
	return nil
}

// checkHook fails with routetable.ErrGuardUnsupported when the main
// ruleset doesn't evaluate the anchors under com.apple, and with an
// ordinary error while a quick pass above that hook can end evaluation
// before it.
func (g *IPv6Guard) checkHook(ctx context.Context) error {
	out, err := g.pf.run(ctx, nil, "-s", "rules")
	if err != nil {
		return err
	}
	switch hooked(out.stdout) {
	case hookMissing:
		return fmt.Errorf("%w: pf's main ruleset has no `anchor %s` (was /etc/pf.conf replaced?)", routetable.ErrGuardUnsupported, appleHook)
	case hookBypassed:
		return fmt.Errorf("firewall: a `pass ... quick` rule above `anchor %s` in pf's main ruleset lets IPv6 past the guard", appleHook)
	}
	return nil
}

// load loads e's anchor and reads it back.
func (g *IPv6Guard) load(ctx context.Context, e routetable.Exempt) (*appliedGuard, error) {
	table, upstream, ports := exemptPrefixes(e), upstreamPrefixes(e), upstreamPorts(e)
	if _, err := g.pf.run(ctx, []byte(anchorText(e.TUN, table, upstream, ports)), "-a", GuardAnchor, "-f", "-"); err != nil {
		return nil, fmt.Errorf("firewall: load the IPv6 guard: %w", err)
	}
	rules, err := g.listRules(ctx)
	if err != nil {
		return nil, err
	}
	if err := saneRules(rules, e.TUN, ports); err != nil {
		return nil, err
	}
	for _, t := range []struct {
		name string
		want []netip.Prefix
	}{{exemptTable, table}, {upstreamTable, upstream}} {
		got, err := g.listTable(ctx, t.name)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(got, t.want) {
			return nil, fmt.Errorf("firewall: pf's table %s holds %d entries unlike the %d loaded", t.name, len(got), len(t.want))
		}
	}
	return &appliedGuard{exempt: e, table: table, upstream: upstream, rules: rules}, nil
}

// listRules lists the anchor's rules; an anchor that doesn't exist has
// none.
func (g *IPv6Guard) listRules(ctx context.Context) ([]string, error) {
	out, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-s", "rules")
	if err != nil {
		if invalidArgument(out) {
			return nil, nil
		}
		return nil, err
	}
	return lines(out.stdout), nil
}

// errNoTable: the table doesn't exist.
var errNoTable = errors.New("firewall: the guard's table doesn't exist")

func (g *IPv6Guard) listTable(ctx context.Context, name string) ([]netip.Prefix, error) {
	out, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-t", name, "-T", "show")
	if err != nil {
		if noTable(out) {
			return nil, fmt.Errorf("%w: %w", errNoTable, err)
		}
		return nil, err
	}
	return parseTable(out.stdout)
}

// intact reports whether the anchor still holds exactly a: its rules as
// listed after the load, line for line, and both tables, entry for entry
// (an entry added is a leak, one removed a refusal).
func (g *IPv6Guard) intact(ctx context.Context, a *appliedGuard) bool {
	rules, err := g.listRules(ctx)
	if err != nil || !slices.Equal(rules, a.rules) {
		return false
	}
	table, err := g.listTable(ctx, exemptTable)
	if err != nil || !slices.Equal(table, a.table) {
		return false
	}
	upstream, err := g.listTable(ctx, upstreamTable)
	return err == nil && slices.Equal(upstream, a.upstream)
}

func (g *IPv6Guard) enabled(ctx context.Context) (bool, error) {
	out, err := g.pf.run(ctx, nil, "-s", "info")
	if err != nil {
		return false, err
	}
	return parseEnabled(out.stdout)
}

// references reads `pfctl -s References`.
func (g *IPv6Guard) references(ctx context.Context) ([]pfReference, bool, error) {
	out, err := g.pf.run(ctx, nil, "-s", "References")
	if err != nil {
		return nil, false, fmt.Errorf("firewall: pf's references: %w", err)
	}
	refs, understood := parseReferences(out.stdout)
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
	if v, ok := byPid(refs, t.pid); ok {
		return v, true, nil
	}
	if !understood || slices.ContainsFunc(refs, func(r pfReference) bool { return r.pid == t.pid }) {
		return 0, false, fmt.Errorf("%w (pfctl pid %d)", errUnreadToken, t.pid)
	}
	return 0, false, nil
}

// enable makes sure pf is on with a reference of the guard's, and the
// record names it: kept while pf is on; taken over from the record (a
// crashed run's, this boot); taken anew when the guard has none, or when
// pf is off (someone ran `pfctl -d`), the old one then released if pf
// still lists it.
func (g *IPv6Guard) enable(ctx context.Context) error {
	on, err := g.enabled(ctx)
	if err != nil {
		return err
	}
	if g.token == nil {
		t, state, err := g.tokens.read()
		switch {
		case err != nil:
			return err
		case state == recordHeld:
			g.token, g.recorded = &t, true
		case state == recordStale:
			if err := g.tokens.remove(); err != nil {
				return err
			}
		}
	}
	if g.token != nil && g.token.value == 0 {
		v, ok, err := g.resolve(ctx, *g.token)
		if err != nil {
			return err
		}
		if ok {
			g.token, g.recorded = &pfToken{value: v, pid: g.token.pid}, false
		} else {
			g.token = nil // gone: the record is replaced below
		}
	}
	if on && g.token != nil {
		if !g.recorded {
			if err := g.tokens.write(*g.token); err != nil {
				return err
			}
			g.recorded = true
		}
		return nil
	}
	old := g.token
	out, err := g.pf.run(ctx, nil, "-E")
	if err != nil {
		return fmt.Errorf("firewall: enable pf: %w", err)
	}
	g.killStates = true // states made while pf was off
	t := pfToken{pid: out.pid}
	v, perr := parseToken(out)
	if perr == nil {
		t.value = v
	} else if v, ok, _ := g.resolve(ctx, t); ok {
		t.value = v
	}
	g.token, g.recorded = &t, false
	if err := g.tokens.write(t); err != nil {
		return err
	}
	g.recorded = true
	if old != nil {
		// pf was off although the guard held a reference. If pfctl -d
		// left it listed, release it now that pf is on again (pf refuses
		// -X while off); best effort: the new one is the record's, and
		// enforcing comes first.
		_ = g.release(ctx, *old)
	}
	if t.value == 0 {
		return fmt.Errorf("%w (pfctl pid %d): %w", errUnreadToken, t.pid, perr)
	}
	return nil
}

// release lets go of t, a reference with a known token: `pfctl -X` if pf
// lists it as taken by the pfctl the guard recorded, nothing if it isn't
// listed (gone already) or is someone else's (the value was reused).
func (g *IPv6Guard) release(ctx context.Context, t pfToken) error {
	refs, _, err := g.references(ctx)
	if err != nil {
		return err
	}
	if referenced(refs, t) != refOurs {
		return nil
	}
	if _, err := g.pf.run(ctx, nil, "-X", fmt.Sprint(t.value)); err != nil {
		return fmt.Errorf("firewall: release pf's reference: %w", err)
	}
	return nil
}

// kill kills the IPv6 states pf holds to or from a destination a doesn't
// exempt: they would pass without the anchor. A state is named by its
// two ends, the host's own address and the other one (`pfctl -k local -k
// remote` for one the host opened, `-k remote -k local` for one opened to
// it); exempt ones and IPv4 ones are left alone. Killing a tunnelled
// connection's state is harmless: the anchor passes it statelessly.
func (g *IPv6Guard) kill(ctx context.Context, a *appliedGuard) error {
	out, err := g.pf.run(ctx, nil, "-s", "states")
	if err != nil {
		return fmt.Errorf("firewall: pf's states: %w", err)
	}
	states := parseStateAddrs(out.stdout)
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
// also flush pf's global state table and statistics). An anchor that
// doesn't exist is empty already, whatever pfctl answers for it.
func (g *IPv6Guard) flush(ctx context.Context) error {
	for _, what := range []string{"rules", "Tables"} {
		out, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-F", what)
		if err == nil {
			continue
		}
		if errors.Is(err, routetable.ErrGuardUnsupported) {
			return err
		}
		if !invalidArgument(out) {
			return fmt.Errorf("firewall: remove the IPv6 guard: %w", err)
		}
		if what == "rules" {
			if rules, lerr := g.listRules(ctx); lerr != nil || len(rules) > 0 {
				return fmt.Errorf("firewall: remove the IPv6 guard: %w", err)
			}
			continue
		}
		for _, name := range []string{exemptTable, upstreamTable} {
			if _, lerr := g.listTable(ctx, name); !errors.Is(lerr, errNoTable) {
				return fmt.Errorf("firewall: remove the IPv6 guard: %w", err)
			}
		}
	}
	return nil
}

// Close flushes the anchor's rules and tables, then releases the
// reference the guard holds, or the one its record holds from this boot
// (a fresh guard's Close is how a crashed run's guard goes), and removes
// the record. A failure, a reference whose token can't be found included,
// leaves the guard open and the record in place, so Close can be tried
// again; the anchor goes before the reference, so pf is never left off
// with the anchor still meant to be in place. With no pfctl at all there
// is nothing to remove.
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
	if t != nil && t.value == 0 {
		v, ok, err := g.resolve(ctx, *t)
		if err != nil {
			return err
		}
		if !ok {
			t = nil // gone
		} else {
			t = &pfToken{value: v, pid: t.pid}
		}
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
// without the Enforcer's own), or, applied, the hook is gone or bypassed,
// pf is off, the anchor's rules or tables changed. pf has no event
// stream. The channel closes when ctx ends.
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
	if g.checkHook(ctx) != nil || !g.intact(ctx, g.applied) {
		return true
	}
	on, err := g.enabled(ctx)
	return err != nil || !on
}
