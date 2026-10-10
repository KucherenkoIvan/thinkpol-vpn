package supervisor

import (
	"net/netip"
	"testing"
	"time"
)

func TestBackoffDoublesAndResets(t *testing.T) {
	b := Backoff{Initial: time.Second, Max: 5 * time.Second, ResetAfter: time.Minute}
	var d time.Duration
	var got []time.Duration
	for range 5 {
		d = b.next(d, time.Second)
		got = append(got, d)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delays %v, want %v", got, want)
		}
	}
	if d = b.next(d, time.Minute); d != time.Second {
		t.Fatalf("after a long run: %v, want the initial delay", d)
	}
}

func TestTransitPlan(t *testing.T) {
	o, err := Options{}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if o.slots() != 256 {
		t.Fatalf("%d slots, want 256 (a /22 of /30s)", o.slots())
	}
	seen := map[netip.Addr]bool{}
	for slot := range o.slots() {
		tr := o.transit(slot)
		for i, p := range []netip.Prefix{tr.root[0], tr.space[0], tr.root[1], tr.space[1]} {
			within := o.TransitIPv4
			if i >= 2 {
				within = o.TransitIPv6
			}
			if !within.Contains(p.Addr()) {
				t.Fatalf("slot %d: %v outside the transit prefixes", slot, p)
			}
			if seen[p.Addr()] {
				t.Fatalf("slot %d: %v used twice", slot, p.Addr())
			}
			seen[p.Addr()] = true
		}
		if tr.root[0].Masked() != tr.space[0].Masked() || tr.root[1].Masked() != tr.space[1].Masked() {
			t.Fatalf("slot %d: ends not on one link: %+v", slot, tr)
		}
	}
	tr := o.transit(1)
	if tr.root[0].String() != "169.254.100.5/30" || tr.space[0].String() != "169.254.100.6/30" ||
		tr.root[1].String() != "fd74:7073:7061:1::1/64" || tr.space[1].String() != "fd74:7073:7061:1::2/64" {
		t.Fatalf("slot 1: %+v", tr)
	}
	if got := linkName(255); len(got) > 15 {
		t.Fatalf("link name %q is too long", got)
	}
}

func TestOptionsAreChecked(t *testing.T) {
	for _, o := range []Options{
		{TransitIPv4: netip.MustParsePrefix("169.254.100.0/31")},
		{TransitIPv4: netip.MustParsePrefix("169.254.100.1/24")},
		{TransitIPv6: netip.MustParsePrefix("fd00::/96")},
		{TransitIPv4: netip.MustParsePrefix("fd00::/48")},
		{Backoff: Backoff{Initial: time.Second, Max: time.Millisecond}},
		{UIDBase: 1<<32 - 10},
	} {
		if _, err := o.withDefaults(); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
}
