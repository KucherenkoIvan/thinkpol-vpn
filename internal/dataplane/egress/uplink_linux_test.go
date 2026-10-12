//go:build linux && !android

package egress

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestFindUplink(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	name := "tp-uplink-" + strconv.Itoa(os.Getpid())
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", append([]string{"-n", name}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	ns, err := netns.GetFromName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close() }()
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	check := func(what string, want Uplink, wantErr error) {
		t.Helper()
		got, err := findUplink(h)
		if !errors.Is(err, wantErr) || got != want {
			t.Fatalf("%s: %+v, %v; want %+v, %v", what, got, err, want, wantErr)
		}
	}

	for _, l := range []string{"wan0", "lan0"} {
		run("link", "add", l, "type", "dummy")
		run("link", "set", l, "up")
	}
	run("addr", "add", "10.9.0.2/24", "dev", "lan0")
	check("no default route", Uplink{}, ErrNoUplink)

	// IPv6 only: its default route's link, with a global address; a
	// unique local one is no internet to masquerade to.
	run("addr", "add", "fd00:9::2/64", "dev", "wan0", "nodad")
	run("-6", "route", "add", "default", "via", "fd00:9::1", "dev", "wan0")
	check("IPv6 with a unique local address", Uplink{Name: "wan0"}, nil)
	run("addr", "add", "2001:db8:9::2/64", "dev", "wan0", "nodad")
	check("IPv6 only", Uplink{Name: "wan0", IPv6: true}, nil)

	// IPv4 picks the uplink; the lower metric wins.
	run("addr", "add", "192.0.2.2/24", "dev", "wan0")
	run("route", "add", "default", "via", "10.9.0.1", "dev", "lan0", "metric", "200")
	run("route", "add", "default", "via", "192.0.2.1", "dev", "wan0", "metric", "100")
	check("dual-stack", Uplink{Name: "wan0", IPv4: true, IPv6: true}, nil)

	// IPv6 leaving by another interface than IPv4's: not this uplink's.
	run("route", "del", "default", "via", "192.0.2.1", "dev", "wan0")
	check("IPv6 elsewhere", Uplink{Name: "lan0", IPv4: true}, nil)

	// IPv6 with only a link-local address: nothing to masquerade to.
	run("addr", "add", "2001:db8:a::2/64", "dev", "lan0", "nodad")
	run("-6", "route", "del", "default", "via", "fd00:9::1", "dev", "wan0")
	run("-6", "route", "add", "default", "via", "fe80::1", "dev", "lan0")
	check("IPv6 on the uplink", Uplink{Name: "lan0", IPv4: true, IPv6: true}, nil)
	run("addr", "del", "2001:db8:a::2/64", "dev", "lan0")
	check("IPv6 link-local only", Uplink{Name: "lan0", IPv4: true}, nil)
}
