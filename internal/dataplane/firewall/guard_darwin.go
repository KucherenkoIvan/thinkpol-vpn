package firewall

import (
	"context"
	"errors"
	"fmt"
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
// Each poll runs pfctl four times.
const guardPoll = 10 * time.Second

// IPv6Guard is routetable's Guard on macOS: it keeps IPv6 from leaving
// around the tunnel (routetable.Exempt) with a pf anchor, GuardAnchor,
// under Apple's `anchor "com.apple/*"` (guardRules lists its rules), and
// the anchor's table of exempt destinations, loaded together by one
// `pfctl -a com.apple/thinkpol -f -`:
//
//	table <thinkpol_exempt6> const persist { <Exempt.Direct's IPv6>, <Exempt.Upstreams>, LinkScoped }
//
// An anchor nothing evaluates guards nothing: Apply first checks the main
// ruleset still has the hook, and without it fails with
// routetable.ErrGuardUnsupported (the health says ipv6_guard_unsupported);
// /etc/pf.conf is never edited. pf is enabled by reference (`pfctl -E`),
// so the guard neither turns off a pf someone else enabled nor leaves pf on
// after it: the token goes to a record in the state directory first thing,
// and Close releases it (`pfctl -X`), but only while `pfctl -s
// References` lists it as taken by the pfctl the record names.
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

	// applied is what the last good load put in place, nil until then
	// and after a failed one.
	applied *appliedGuard
	// token is the reference this guard holds (nil: none); recorded says
	// the record has it. lostToken: `pfctl -E` took a reference whose
	// token it didn't print readably; it keeps pf on, can't be released,
	// and isn't taken again.
	token     *pfToken
	recorded  bool
	lostToken bool
	closed    bool
}

// appliedGuard is a guard Apply put in place: for exempt, the table it
// loaded, and the anchor's rules as pfctl listed them after the load.
type appliedGuard struct {
	exempt routetable.Exempt
	table  []netip.Prefix
	rules  []string
}

var _ routetable.Guard = (*IPv6Guard)(nil)

// errClosed: the guard was closed.
var errClosed = errors.New("firewall: the IPv6 guard is closed")

// NewIPv6Guard returns the host's guard, its record in netcfg.StateDir.
// Nothing is in place until Apply; Close removes what is there, a crashed
// run's anchor and reference included.
func NewIPv6Guard() *IPv6Guard {
	return newIPv6Guard(execPfctl{path: pfctlPath, timeout: pfctlTimeout}, tokenStore{dir: netcfg.StateDir, boot: bootSession}, guardPoll)
}

func newIPv6Guard(pf pfctl, tokens tokenStore, poll time.Duration) *IPv6Guard {
	return &IPv6Guard{pf: pf, tokens: tokens, poll: poll}
}

// Apply puts e in place: the anchor (rules and table in one load), then
// pf enabled by a reference of its own. Applying what is in place again
// only reads it back (the hook, the rules exactly as listed after the
// load, every table entry, pf enabled) and reloads if anything differs.
// A failed load leaves what was there (a pf transaction), a guard at
// least as strict as either.
func (g *IPv6Guard) Apply(ctx context.Context, e routetable.Exempt) error {
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
	if err := g.checkHook(ctx); err != nil {
		return err
	}
	if a := g.applied; a == nil || !a.exempt.Equal(e) || !g.intact(ctx, a) {
		g.applied = nil
		a, err := g.load(ctx, e)
		if err != nil {
			return err
		}
		g.applied = a
	}
	// After the load, so pf comes on with the guard in place; a failure
	// here leaves the anchor applied, and the retry only enables.
	return g.enable(ctx)
}

// checkHook fails with routetable.ErrGuardUnsupported when the main
// ruleset doesn't evaluate the anchors under com.apple.
func (g *IPv6Guard) checkHook(ctx context.Context) error {
	out, err := g.pf.run(ctx, nil, "-s", "rules")
	if err != nil {
		return err
	}
	if !hooked(out.stdout) {
		return fmt.Errorf("%w: pf's main ruleset has no `anchor %s` (was /etc/pf.conf replaced?)", routetable.ErrGuardUnsupported, appleHook)
	}
	return nil
}

// load loads e's anchor and reads it back.
func (g *IPv6Guard) load(ctx context.Context, e routetable.Exempt) (*appliedGuard, error) {
	table := exemptTable(e)
	if _, err := g.pf.run(ctx, []byte(anchorText(e.TUN, table)), "-a", GuardAnchor, "-f", "-"); err != nil {
		return nil, fmt.Errorf("firewall: load the IPv6 guard: %w", err)
	}
	rules, err := g.listRules(ctx)
	if err != nil {
		return nil, err
	}
	if err := saneRules(rules, e.TUN); err != nil {
		return nil, err
	}
	got, err := g.listTable(ctx)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(got, table) {
		return nil, fmt.Errorf("firewall: pf's table of the guard holds %d entries unlike the %d loaded", len(got), len(table))
	}
	return &appliedGuard{exempt: e, table: table, rules: rules}, nil
}

func (g *IPv6Guard) listRules(ctx context.Context) ([]string, error) {
	out, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-s", "rules")
	if err != nil {
		return nil, err
	}
	return lines(out.stdout), nil
}

func (g *IPv6Guard) listTable(ctx context.Context) ([]netip.Prefix, error) {
	out, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-t", guardTable, "-T", "show")
	if err != nil {
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
	table, err := g.listTable(ctx)
	return err == nil && slices.Equal(table, a.table)
}

func (g *IPv6Guard) enabled(ctx context.Context) (bool, error) {
	out, err := g.pf.run(ctx, nil, "-s", "info")
	if err != nil {
		return false, err
	}
	return parseEnabled(out.stdout)
}

// enable makes sure pf is on with a reference of the guard's: kept while
// pf is on; taken over from the record (a crashed run's, this boot); taken
// anew when the guard has none, or when pf is off (someone ran `pfctl
// -d`), the old one then released if pf still lists it.
func (g *IPv6Guard) enable(ctx context.Context) error {
	on, err := g.enabled(ctx)
	if err != nil {
		return err
	}
	if g.token == nil && !g.lostToken {
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
	if on && (g.token != nil || g.lostToken) {
		if g.token != nil && !g.recorded {
			if err := g.tokens.write(*g.token); err != nil {
				return err
			}
			g.recorded = true
		}
		return nil
	}
	if !on {
		g.lostToken = false // pf is off: no reference is left, a lost one neither
	}
	old := g.token
	out, err := g.pf.run(ctx, nil, "-E")
	if err != nil {
		return fmt.Errorf("firewall: enable pf: %w", err)
	}
	v, err := parseToken(out)
	if err != nil {
		g.lostToken = true
		return err
	}
	g.token, g.recorded = &pfToken{value: v, pid: out.pid}, false
	if err := g.tokens.write(*g.token); err != nil {
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
	return nil
}

// release lets go of t: `pfctl -X` if pf lists it as taken by the pfctl
// the guard recorded, nothing if it isn't listed (gone already) or is
// someone else's (the value was reused).
func (g *IPv6Guard) release(ctx context.Context, t pfToken) error {
	out, err := g.pf.run(ctx, nil, "-s", "References")
	if err != nil {
		return fmt.Errorf("firewall: release pf's reference: %w", err)
	}
	if referenced(out.stdout, t) != refOurs {
		return nil
	}
	if _, err := g.pf.run(ctx, nil, "-X", fmt.Sprint(t.value)); err != nil {
		return fmt.Errorf("firewall: release pf's reference: %w", err)
	}
	return nil
}

// Close flushes the anchor's rules and tables, then releases the
// reference the guard holds, or the one its record holds from this boot
// (a fresh guard's Close is how a crashed run's guard goes), and removes
// the record. A failure leaves the guard open and the record in place, so
// Close can be tried again; the anchor goes before the reference, so
// pf is never left off with the anchor still meant to be in place. With no
// pfctl at all there is nothing to remove.
func (g *IPv6Guard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	ctx := context.Background()
	g.applied = nil
	// The anchor's rules, then its tables: `-F all` would also flush pf's
	// global state table and statistics.
	for _, what := range []string{"rules", "Tables"} {
		if _, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-F", what); err != nil {
			if errors.Is(err, routetable.ErrGuardUnsupported) {
				break
			}
			return fmt.Errorf("firewall: remove the IPv6 guard: %w", err)
		}
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
	if t != nil {
		if err := g.release(ctx, *t); err != nil && !errors.Is(err, routetable.ErrGuardUnsupported) {
			return err
		}
	}
	if err := g.tokens.remove(); err != nil {
		return err
	}
	g.token, g.recorded, g.lostToken, g.closed = nil, false, false, true
	return nil
}

// Watch polls the guard every guardPoll while it is applied, and
// signals, coalesced, when it isn't whole any more: the hook gone from the
// main ruleset, pf off, the anchor's rules or table changed. pf has no
// event stream. The channel closes when ctx ends.
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

// broken reports whether the applied guard isn't whole now; reading it
// back failing counts as not whole.
func (g *IPv6Guard) broken(ctx context.Context) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.applied == nil || ctx.Err() != nil {
		return false
	}
	if g.checkHook(ctx) != nil || !g.intact(ctx, g.applied) {
		return true
	}
	on, err := g.enabled(ctx)
	return err != nil || !on
}
