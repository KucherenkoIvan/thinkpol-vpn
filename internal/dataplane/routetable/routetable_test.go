package routetable_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

func set(t testing.TB, prefixes ...string) *lists.Set {
	t.Helper()
	var b lists.Builder
	for _, p := range prefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := b.Build()
	return s
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func routeStrings(cfg netcfg.Config) []string {
	var out []string
	for _, r := range cfg.Routes {
		out = append(out, r.String())
	}
	return out
}

func ruleStrings(cfg netcfg.Config) []string {
	var out []string
	for _, r := range cfg.Rules {
		out = append(out, r.String())
	}
	return out
}

var overlay = []netip.Prefix{pfx("100.64.0.0/10"), pfx("fd12:3456:789a::/48")}

// up is a survey of a device whose TUN is up.
func up(onLink ...string) netcfg.Survey {
	s := netcfg.Survey{Links: []netcfg.Link{{Name: "eth0", Up: true}, {Name: "lo", Up: true}, {Name: "thinkpol0", Up: true}, {Name: "wlan0"}}}
	for _, p := range onLink {
		s.OnLink = append(s.OnLink, pfx(p))
	}
	return s
}

func TestConfigLayout(t *testing.T) {
	w := routetable.Want{
		TUN:     "thinkpol0",
		Overlay: overlay,
		Direct:  set(t, "10.0.0.0/8", "192.168.0.0/16", "198.51.100.0/24", "fc00::/7", "fe80::/10"),
		// Endpoints: one inside a direct prefix, one adjacent to one (the
		// throws merge), one IPv4-mapped, one twice.
		Bypass: []netip.Addr{
			netip.MustParseAddr("10.1.2.3"),
			netip.MustParseAddr("198.51.101.0"),
			netip.MustParseAddr("::ffff:203.0.113.9"),
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("2001:db8::1"),
		},
		IPv6: true,
	}
	survey := up(
		"192.168.1.0/24", "fe80::/64", "2001:db8:1::/64",
		"100.64.0.0/10", "fd12:3456:789a::/48", // the TUN's own
		"fd12:3456:789a:1::/64",                     // a ULA prefix inside the overlay
		"8.0.0.0/8", "1.1.1.0/24", "203.0.113.9/32", // public: never trusted
		"172.16.0.0/24", // private, but not direct by the rules
	)
	cfg := routetable.PolicyRouting(w, survey)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"100.64.0.0/10 dev thinkpol0 table 29808",
		"unreachable 100.64.0.0/10 metric 2048 table 29808",
		"fd12:3456:789a::/48 dev thinkpol0 table 29808",
		"unreachable fd12:3456:789a::/48 metric 2048 table 29808",
		"0.0.0.0/0 dev thinkpol0 table 29808",
		"::/0 dev thinkpol0 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw 10.0.0.0/8 table 29808",
		"throw 192.168.0.0/16 table 29808",
		"throw 198.51.100.0/24 table 29808",
		"throw 198.51.101.0/32 table 29808",
		"throw 203.0.113.9/32 table 29808",
		"throw 2001:db8::1/128 table 29808",
		"throw fc00::/7 table 29808",
		"throw fe80::/10 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
	wantRules := []string{
		"IPv4 rule 5298 oif eth0 table 0 suppress_prefixlength 0",
		"IPv4 rule 5298 oif wlan0 table 0 suppress_prefixlength 0",
		"IPv4 rule 5299 to 100.64.0.0/10 table 29808",
		"IPv4 rule 5300 to 192.168.1.0/24 table 0 suppress_prefixlength 0",
		"IPv4 rule 5301 not fwmark 0x7470 table 29808",
		"IPv6 rule 5298 oif eth0 table 0 suppress_prefixlength 0",
		"IPv6 rule 5298 oif wlan0 table 0 suppress_prefixlength 0",
		"IPv6 rule 5299 to fd12:3456:789a::/48 table 29808",
		"IPv6 rule 5300 to fe80::/64 table 0 suppress_prefixlength 0",
		"IPv6 rule 5301 not fwmark 0x7470 table 29808",
	}
	if got := ruleStrings(cfg); !slices.Equal(got, wantRules) {
		t.Errorf("rules:\n got %q\nwant %q", got, wantRules)
	}
}

// Without IPv6 in the TUN, IPv6 meets only the unreachable default (and
// the throws): it is dropped, never sent around the tunnel.
func TestConfigWithoutIPv6(t *testing.T) {
	cfg := routetable.PolicyRouting(routetable.Want{TUN: "thinkpol0", Direct: set(t, "fe80::/10")}, up())
	want := []string{
		"0.0.0.0/0 dev thinkpol0 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw fe80::/10 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
}

// With the TUN down (or gone), nothing goes to it: both families and the
// overlay are unreachable but for the throws.
func TestConfigWithTheTUNDown(t *testing.T) {
	s := up()
	s.Links[2].Up = false
	w := routetable.Want{TUN: "thinkpol0", Overlay: overlay, Direct: set(t, "198.51.100.0/24"), IPv6: true}
	if routetable.TUNUp(w, s) {
		t.Fatal("TUNUp with the TUN down")
	}
	want := []string{
		"unreachable 100.64.0.0/10 metric 2048 table 29808",
		"unreachable fd12:3456:789a::/48 metric 2048 table 29808",
		"unreachable 0.0.0.0/0 metric 2048 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw 198.51.100.0/24 table 29808",
	}
	if got := routeStrings(routetable.PolicyRouting(w, s)); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
	if routetable.TUNUp(routetable.Want{TUN: "gone0"}, s) {
		t.Error("TUNUp for a TUN that isn't there")
	}
}

// All of IPv4 direct (no overlay network claiming part of it) is a throw
// default, not a second default route of the same identity.
func TestConfigWithEverythingDirect(t *testing.T) {
	cfg := routetable.PolicyRouting(routetable.Want{TUN: "thinkpol0", Direct: set(t, "0.0.0.0/0"), IPv6: true}, up())
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"::/0 dev thinkpol0 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw 0.0.0.0/0 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
}

func TestTrustedOnLink(t *testing.T) {
	direct := lists.Local()
	for p, want := range map[string]bool{
		"192.168.1.0/24": true, "10.0.0.0/8": true, "172.16.0.0/12": true, "169.254.0.0/16": true,
		"fe80::/64": true, "fd00:1::/48": true, "192.168.1.7/32": true,
		"203.0.113.0/24": false, "203.0.113.128/25": false, "1.1.1.0/24": false, "198.51.100.1/32": false,
		"2001:db8:1::/64": false, "2001:4860:4860::/64": false, "100.64.0.0/24": false, "203.0.112.0/23": false,
		"8.0.0.0/8": false, "0.0.0.0/1": false, "224.0.0.0/3": false, "11.0.0.0/7": false,
		"2001:db8::/32": false, "::/1": false, "0.0.0.0/0": false,
	} {
		if got := routetable.TrustedOnLink(pfx(p), direct); got != want {
			t.Errorf("%s: trusted %v, want %v", p, got, want)
		}
	}
	// Where the rules tunnel part of a private range, an on-link subnet
	// over it isn't trusted: the network can't widen what goes direct.
	tunneled := direct.Minus(set(t, "10.20.0.0/16"))
	if routetable.TrustedOnLink(pfx("10.0.0.0/8"), tunneled) || !routetable.TrustedOnLink(pfx("10.21.0.0/16"), tunneled) {
		t.Error("an on-link subnet over a tunneled private range is trusted, or one beside it isn't")
	}
	if routetable.TrustedOnLink(pfx("192.168.1.0/24"), nil) {
		t.Error("trusted with nothing direct")
	}
}

func TestWantEqual(t *testing.T) {
	a := routetable.Want{TUN: "t", Overlay: overlay, Direct: set(t, "10.0.0.0/8"),
		Bypass: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}}
	b := a
	b.Direct = set(t, "10.0.0.0/9", "10.128.0.0/9")
	b.Bypass = []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("::ffff:192.0.2.1")}
	b.Overlay = []netip.Prefix{overlay[1], overlay[0]}
	if !a.Equal(b) {
		t.Error("the same routes compare unequal")
	}
	for name, mod := range map[string]func(*routetable.Want){
		"tun":     func(w *routetable.Want) { w.TUN = "u" },
		"ipv6":    func(w *routetable.Want) { w.IPv6 = true },
		"direct":  func(w *routetable.Want) { w.Direct = nil },
		"bypass":  func(w *routetable.Want) { w.Bypass = w.Bypass[:1] },
		"overlay": func(w *routetable.Want) { w.Overlay = w.Overlay[:1] },
	} {
		c := a
		mod(&c)
		if a.Equal(c) {
			t.Errorf("%s: unequal wants compare equal", name)
		}
	}
}

// fakeConfigurator records Applies and lets the test signal Watch.
type fakeConfigurator struct {
	mu      sync.Mutex
	applies []netcfg.Config
	fail    bool
	failErr error // what a failing Apply returns; nil: a plain error
	closed  bool
	survey  netcfg.Survey
	events  chan struct{}
	order   *[]string // what was closed, in order
	// watchErr: what Watch returns; nil: it watches.
	watchErr error
	// attempts: when each Apply was called, failed ones included.
	attempts []time.Time
}

// setFailErr makes Apply fail with err.
func (f *fakeConfigurator) setFailErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail, f.failErr = true, err
}

func (f *fakeConfigurator) setWatchErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watchErr = err
}

func (f *fakeConfigurator) Apply(_ context.Context, cfg netcfg.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, time.Now())
	if f.fail {
		if f.failErr != nil {
			return f.failErr
		}
		return errors.New("the kernel said no")
	}
	f.applies = append(f.applies, cfg)
	return nil
}

// attemptTimes is when each Apply was called, failed ones included.
func (f *fakeConfigurator) attemptTimes() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.attempts)
}

func (f *fakeConfigurator) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applies)
}

func (f *fakeConfigurator) setFail(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

func (f *fakeConfigurator) DefaultRoute(context.Context, netcfg.Family) (netcfg.Route, error) {
	return netcfg.Route{}, netcfg.ErrNoDefaultRoute
}

func (f *fakeConfigurator) Survey(context.Context) (netcfg.Survey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.survey, nil
}

func (f *fakeConfigurator) Watch(ctx context.Context) (<-chan struct{}, error) {
	f.mu.Lock()
	err := f.watchErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := make(chan struct{})
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-f.events:
				select {
				case out <- struct{}{}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

func (f *fakeConfigurator) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	if f.order != nil {
		*f.order = append(*f.order, "routes")
	}
	return nil
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEnforcerAppliesChangesAndReappliesOnEvents(t *testing.T) {
	survey := up()
	survey.ForeignRules = []int{5210, 5270, 5400}
	f := &fakeConfigurator{events: make(chan struct{}), survey: survey}
	e := routetable.Open(f, nil)
	ctx := context.Background()
	if st := e.Status(); st.Enforced {
		t.Errorf("enforced before the first Enforce: %+v", st)
	}
	w := routetable.Want{TUN: "thinkpol0", Direct: set(t, "10.0.0.0/8")}
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	if n := f.count(); n != 1 {
		t.Fatalf("%d Applies for one Want twice, want 1", n)
	}
	// This OS's layout: three routes and two rules ahead on Linux.
	routes, ahead := len(routetable.Config(w, survey).Routes), routetable.Ahead(w, survey)
	if runtime.GOOS == "linux" && (routes != 3 || ahead != 2) {
		t.Errorf("Linux layout: %d routes, %d ahead", routes, ahead)
	}
	if st := e.Status(); !st.Enforced || st.Routes != routes || st.RulesAhead != ahead || st.Error != "" {
		t.Errorf("status %+v", st)
	}
	// After an Enforce the watcher checks once, for what it missed.
	eventually(t, "the check after Enforce", func() bool { return e.Status().Reapplies == 1 })
	// A burst of events is one re-Apply of the same config.
	for range 5 {
		f.events <- struct{}{}
	}
	eventually(t, "a re-Apply", func() bool { return f.count() >= 3 })
	time.Sleep(400 * time.Millisecond)
	if n := f.count(); n != 3 {
		t.Fatalf("%d Applies after a burst of events, want 3", n)
	}
	if st := e.Status(); st.Reapplies != 2 {
		t.Errorf("reapplies %d, want 2", st.Reapplies)
	}
	f.mu.Lock()
	same := slices.Equal(routeStrings(f.applies[0]), routeStrings(f.applies[1]))
	f.mu.Unlock()
	if !same {
		t.Error("the re-Apply applied another config")
	}

	// A re-Apply that fails says so, and is retried until it works.
	f.setFail(true)
	f.events <- struct{}{}
	eventually(t, "a failed re-Apply in the status", func() bool {
		st := e.Status()
		return !st.Enforced && st.Error == routetable.ErrorReapply
	})
	f.setFail(false)
	eventually(t, "a retry RetryAfter after the failed re-Apply", func() bool { return e.Status().Enforced })

	// A failed Enforce keeps what was in place and says so; the same Want
	// again is tried again, not skipped.
	f.setFail(true)
	w2 := w
	w2.Direct = nil
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	if st := e.Status(); st.Enforced || st.Error != routetable.ErrorApply {
		t.Errorf("status after a failed Enforce: %+v", st)
	}
	f.setFail(false)
	n := f.count()
	if err := e.Enforce(ctx, w2); err != nil {
		t.Fatal(err)
	}
	if f.count() != n+1 || !e.Status().Enforced {
		t.Errorf("the failed Want wasn't applied again: %d Applies, %+v", f.count()-n, e.Status())
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.closed {
		t.Error("Close didn't close the configurator")
	}
	if err := e.Enforce(ctx, w); !errors.Is(err, netcfg.ErrClosed) {
		t.Errorf("Enforce after Close: %v", err)
	}
}

// While the routes fail, events don't retry them every debounce: a failing
// Apply's undo removes rules of ours, itself an event, so a Watch fires
// after every attempt. The retries come RetryAfter apart; before the
// failure, an event re-applies a debounce later.
func TestAFailingApplyIsRetriedAtRetryAfterNotOnEachEvent(t *testing.T) {
	t.Parallel()
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	e := routetable.Open(f, nil)
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Enforce(ctx, routetable.Want{TUN: "thinkpol0"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the check after Enforce", func() bool { return e.Status().Reapplies == 1 })
	attempts := f.attemptTimes
	// Not failing: an event re-applies a debounce later, not a retry later.
	n, sent := len(attempts()), time.Now()
	f.events <- struct{}{}
	eventually(t, "a re-Apply on an event", func() bool { return len(attempts()) > n })
	if took := time.Since(sent); took > time.Second {
		t.Errorf("an event while not failing re-applied %v later, want a debounce", took)
	}

	// Failing: events keep coming, as the undo of each attempt makes them.
	f.setFail(true)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case f.events <- struct{}{}:
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()
	eventually(t, "a failed re-Apply", func() bool { return e.Status().Error == routetable.ErrorReapply })
	eventually(t, "a retry while failing", func() bool { return len(attempts()) >= n+3 })
	time.Sleep(time.Second) // room for a retry that comes too soon
	cancel()
	all := attempts()
	failed := all[n+1:] // the first failed attempt on
	if len(failed) < 2 {
		t.Fatalf("%d attempts while failing over more than RetryAfter, want a retry", len(failed))
	}
	for i := 1; i < len(failed); i++ {
		if gap := failed[i].Sub(failed[i-1]); gap < routetable.RetryAfter-10*time.Millisecond {
			t.Errorf("attempt %d came %v after the one before, want RetryAfter (%v): %d attempts in all", i, gap, routetable.RetryAfter, len(failed))
			break
		}
	}
}

// The watcher's check after a failed Enforce waits for the retry too:
// RetryAfter after the failed attempt, not a debounce later.
func TestTheCheckAfterAFailedEnforceWaitsForRetryAfter(t *testing.T) {
	t.Parallel()
	f := &fakeConfigurator{events: make(chan struct{}), survey: up(), fail: true}
	e := routetable.Open(f, nil)
	t.Cleanup(func() { _ = e.Close() })
	if err := e.Enforce(t.Context(), routetable.Want{TUN: "thinkpol0"}); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	eventually(t, "a retry", func() bool { return len(f.attemptTimes()) >= 2 })
	a := f.attemptTimes()
	if gap := a[1].Sub(a[0]); gap < routetable.RetryAfter-10*time.Millisecond {
		t.Errorf("the failed Enforce was tried again %v later, want RetryAfter (%v)", gap, routetable.RetryAfter)
	}
}

// The fix while the routes fail (the TUN coming up, say) is taken by the
// next retry: at most RetryAfter after its event, not a retry later still.
func TestAFixWhileFailingIsTakenWithinRetryAfter(t *testing.T) {
	t.Parallel()
	const slack = 500 * time.Millisecond
	f := &fakeConfigurator{events: make(chan struct{}), survey: up(), fail: true}
	e := routetable.Open(f, nil)
	t.Cleanup(func() { _ = e.Close() })
	if err := e.Enforce(t.Context(), routetable.Want{TUN: "thinkpol0"}); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	f.setFail(false)
	sent := time.Now()
	f.events <- struct{}{}
	eventually(t, "the routes in after the fix", func() bool { return e.Status().Enforced })
	if took := time.Since(sent); took > routetable.RetryAfter+slack {
		t.Errorf("the fix was taken %v after its event, want at most RetryAfter (%v)", took, routetable.RetryAfter)
	}
}

// While the routes fail, the guard's events don't push their retry back:
// it comes RetryAfter after the failed attempt however often the guard's
// Watch fires meanwhile.
func TestGuardEventsDontPushTheRoutesRetryBack(t *testing.T) {
	t.Parallel()
	e, f, g := failingRig(t, routetable.Want{TUN: "thinkpol0"})
	f.events <- struct{}{}
	eventually(t, "a failed re-Apply", func() bool { return e.Status().Error == routetable.ErrorReapply })
	a := f.attemptTimes()
	n, failed, k := len(a), a[len(a)-1], g.count()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case g.events <- struct{}{}:
				time.Sleep(300 * time.Millisecond)
			}
		}
	}()
	eventually(t, "the routes retried", func() bool { return len(f.attemptTimes()) > n })
	cancel()
	if gap := f.attemptTimes()[n].Sub(failed); gap > routetable.RetryAfter+time.Second {
		t.Errorf("the routes were retried %v after the failed attempt, want RetryAfter (%v)", gap, routetable.RetryAfter)
	}
	if g.count() < k+3 {
		t.Errorf("%d guard Applies while the routes failed, want the guard's events taken", g.count()-k)
	}
}

// A kernel that can't hold the table at all stops the enforcer for good:
// no retries, and the status says why.
func TestEnforcerStopsOnAnUnsupportedKernel(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), fail: true, failErr: fmt.Errorf("netcfg: old kernel: %w", errors.ErrUnsupported)}
	e := routetable.Open(f, nil)
	defer func() { _ = e.Close() }()
	w := routetable.Want{TUN: "thinkpol0"}
	if err := e.Enforce(context.Background(), w); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Enforce: %v", err)
	}
	if st := e.Status(); st.Enforced || st.Error != routetable.ErrorUnsupported {
		t.Errorf("status %+v", st)
	}
	f.setFail(false)
	time.Sleep(routetable.RetryAfter + time.Second)
	if n := f.count(); n != 0 {
		t.Errorf("%d Applies after an unsupported kernel, want none", n)
	}
	if err := e.Enforce(context.Background(), w); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Enforce again: %v", err)
	}
}

// A corrupt route record netcfg found is counted in the status with the
// unowned routes, and warned of once, by its path and why, however often
// the table is put back while it is there unchanged; once it goes and
// comes back, or comes back with a new reason or mtime, it is warned of
// again.
func TestACorruptRecordIsCountedAndWarnedOnceWhileUnchanged(t *testing.T) {
	const path, reason = "/state/netcfg/overlay.routes.corrupt-boot", "no boot session"
	f := &fakeConfigurator{survey: up()}
	f.survey.CorruptRecords = []netcfg.CorruptRecord{{Path: path, Reason: reason}}
	f.survey.UnownedRoutes = 3
	var buf lockedBuffer
	e := routetable.OpenWithClock(f, nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), (&fakeClock{now: time.Unix(0, 0)}).read)
	defer func() { _ = e.Close() }()
	if err := e.Enforce(t.Context(), routetable.Want{TUN: "thinkpol0"}); err != nil {
		t.Fatal(err)
	}
	routetable.PauseWatching(e)
	if st := e.Status(); st.CorruptRecords != 1 || st.UnownedRoutes != 3 {
		t.Errorf("CorruptRecords %d, UnownedRoutes %d, want 1, 3", st.CorruptRecords, st.UnownedRoutes)
	}
	routetable.Reapply(t.Context(), e)
	if w := buf.lines("corrupt route record"); len(w) != 1 || !strings.Contains(w[0], path) || !strings.Contains(w[0], reason) {
		t.Errorf("warns %q, want one naming %s and %q", w, path, reason)
	}
	// Removed by hand: no longer counted.
	f.mu.Lock()
	f.survey.CorruptRecords, f.survey.UnownedRoutes = nil, 0
	f.mu.Unlock()
	routetable.Reapply(t.Context(), e)
	if st := e.Status(); st.CorruptRecords != 0 || st.UnownedRoutes != 0 {
		t.Errorf("CorruptRecords %d, UnownedRoutes %d after the record went, want 0", st.CorruptRecords, st.UnownedRoutes)
	}
	// Corrupted again: warned again, and again for a new reason or mtime.
	for i, r := range []netcfg.CorruptRecord{
		{Path: path, Reason: reason},
		{Path: path, Reason: "bad line 2 after the boot line: bad scope"},
		{Path: path, Reason: "bad line 2 after the boot line: bad scope", Modified: time.Unix(60, 0)},
	} {
		f.mu.Lock()
		f.survey.CorruptRecords = []netcfg.CorruptRecord{r}
		f.mu.Unlock()
		routetable.Reapply(t.Context(), e)
		routetable.Reapply(t.Context(), e)
		if w := buf.lines("corrupt route record"); len(w) != i+2 || !strings.Contains(w[i+1], r.Reason) {
			t.Errorf("after %+v: warns %q, want %d", r, w, i+2)
		}
	}
}
