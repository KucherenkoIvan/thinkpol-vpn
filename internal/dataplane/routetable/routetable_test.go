package routetable_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
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

func TestConfigLayout(t *testing.T) {
	w := routetable.Want{
		TUN:     "thinkpol0",
		Overlay: overlay,
		Direct:  set(t, "10.0.0.0/8", "198.51.100.0/24", "fc00::/7"),
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
	survey := netcfg.Survey{OnLink: []netip.Prefix{
		pfx("192.168.1.0/24"), pfx("fe80::/64"), pfx("2001:db8:1::/64"),
		pfx("100.64.0.0/10"), pfx("fd12:3456:789a::/48"), // the TUN's own
		pfx("8.0.0.0/8"), pfx("2001:db8::/32"), // too wide to trust
	}}
	cfg := routetable.Config(w, survey)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"0.0.0.0/0 dev thinkpol0 table 29808",
		"unreachable 0.0.0.0/0 metric 2048 table 29808",
		"::/0 dev thinkpol0 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw 10.0.0.0/8 table 29808",
		"throw 198.51.100.0/24 table 29808",
		"throw 198.51.101.0/32 table 29808",
		"throw 203.0.113.9/32 table 29808",
		"throw 2001:db8::1/128 table 29808",
		"throw fc00::/7 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
	wantRules := []string{
		"IPv4 rule 5300 to 100.64.0.0/10 table 0",
		"IPv4 rule 5300 to 192.168.1.0/24 table 0",
		"IPv4 rule 5301 not fwmark 0x7470 table 29808",
		"IPv6 rule 5300 to 2001:db8:1::/64 table 0",
		"IPv6 rule 5300 to fd12:3456:789a::/48 table 0",
		"IPv6 rule 5300 to fe80::/64 table 0",
		"IPv6 rule 5301 not fwmark 0x7470 table 29808",
	}
	if got := ruleStrings(cfg); !slices.Equal(got, wantRules) {
		t.Errorf("rules:\n got %q\nwant %q", got, wantRules)
	}
}

// Without IPv6 in the TUN, IPv6 meets only the unreachable default (and
// the throws): it is dropped, never sent around the tunnel.
func TestConfigWithoutIPv6(t *testing.T) {
	cfg := routetable.Config(routetable.Want{TUN: "thinkpol0", Direct: set(t, "fe80::/10")}, netcfg.Survey{})
	want := []string{
		"0.0.0.0/0 dev thinkpol0 table 29808",
		"unreachable 0.0.0.0/0 metric 2048 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw fe80::/10 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
}

// All of IPv4 direct (no overlay network claiming part of it) is a throw
// default, not a second default route of the same identity.
func TestConfigWithEverythingDirect(t *testing.T) {
	cfg := routetable.Config(routetable.Want{TUN: "thinkpol0", Direct: set(t, "0.0.0.0/0"), IPv6: true}, netcfg.Survey{})
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
	for p, want := range map[string]bool{
		"192.168.1.0/24": true, "10.0.0.0/8": true, "172.16.0.0/12": true, "169.254.0.0/16": true,
		"203.0.113.0/24": true, "203.0.113.128/25": true, "fe80::/64": true, "fd00:1::/48": true, "2001:db8:1::/64": true,
		"203.0.112.0/23": false, "8.0.0.0/8": false, "0.0.0.0/1": false, "224.0.0.0/3": false, "11.0.0.0/7": false,
		"2001:db8::/32": false, "::/1": false, "0.0.0.0/0": false,
	} {
		if got := routetable.TrustedOnLink(pfx(p)); got != want {
			t.Errorf("%s: trusted %v, want %v", p, got, want)
		}
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
	closed  bool
	survey  netcfg.Survey
	events  chan struct{}
}

func (f *fakeConfigurator) Apply(_ context.Context, cfg netcfg.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("the kernel said no")
	}
	f.applies = append(f.applies, cfg)
	return nil
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
	f := &fakeConfigurator{events: make(chan struct{}), survey: netcfg.Survey{ForeignRules: []int{5210, 5270, 5400}}}
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
	if st := e.Status(); !st.Enforced || st.Routes != 4 || st.RulesAhead != 2 || st.Error != "" {
		t.Errorf("status %+v", st)
	}
	// A burst of events is one re-Apply of the same config.
	for range 5 {
		f.events <- struct{}{}
	}
	eventually(t, "a re-Apply", func() bool { return f.count() >= 2 })
	time.Sleep(400 * time.Millisecond)
	if n := f.count(); n != 2 {
		t.Fatalf("%d Applies after a burst of events, want 2", n)
	}
	if st := e.Status(); st.Reapplies != 1 {
		t.Errorf("reapplies %d, want 1", st.Reapplies)
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
	eventually(t, "a retry within RetryAfter", func() bool { return e.Status().Enforced })

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
