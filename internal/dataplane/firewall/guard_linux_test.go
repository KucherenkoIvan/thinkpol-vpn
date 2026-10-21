//go:build linux && !android

package firewall_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// pair is a device namespace whose eth0 is a veth to a gateway namespace,
// which answers for the "sites" on its lo; the device also has a TUN-like
// dummy thinkpol0. No route table: what isn't guarded leaves by eth0.
type pair struct{ dev, gw string }

const (
	foreign6  = "2001:db8:ab::7" // a site only the tunnel may reach
	domestic6 = "2001:db8:d0::7" // a direct site
)

func newPair(t *testing.T) *pair {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	p := &pair{dev: "fw-" + hex.EncodeToString(b), gw: "fwgw-" + hex.EncodeToString(b)}
	for _, ns := range []string{p.dev, p.gw} {
		if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
			t.Fatalf("ip netns add: %v: %s", err, out)
		}
		t.Cleanup(func() { _, _ = exec.Command("ip", "netns", "del", ns).CombinedOutput() })
	}
	p.ip(t, p.dev, "link", "add", "eth0", "type", "veth", "peer", "name", "gw0", "netns", p.gw)
	for _, args := range [][]string{
		{"link", "add", "thinkpol0", "type", "dummy"},
		{"link", "set", "lo", "up"},
		{"link", "set", "eth0", "up"},
		{"link", "set", "thinkpol0", "up"},
		{"addr", "add", "192.0.2.2/24", "dev", "eth0"},
		{"addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad"},
		{"route", "add", "default", "via", "192.0.2.1"},
		{"-6", "route", "add", "default", "via", "2001:db8:1::1"},
	} {
		p.ip(t, p.dev, args...)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "set", "gw0", "up"},
		{"addr", "add", "192.0.2.1/24", "dev", "gw0"},
		{"addr", "add", "2001:db8:1::1/64", "dev", "gw0", "nodad"},
		{"addr", "add", foreign6 + "/128", "dev", "lo"},
		{"addr", "add", domestic6 + "/128", "dev", "lo"},
		{"addr", "add", "2a00:2::1/128", "dev", "lo"},
		{"addr", "add", "2a00:1::1/128", "dev", "lo"},
	} {
		p.ip(t, p.gw, args...)
	}
	return p
}

func (p *pair) ip(t *testing.T, ns string, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", append([]string{"-n", ns}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip -n %s %s: %v: %s", ns, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (p *pair) guard(t *testing.T) *firewall.IPv6Guard {
	t.Helper()
	g, err := firewall.NewIPv6GuardInNamespace("/run/netns/" + p.dev)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// ping says whether one ping from the device, with ping's own extra
// arguments (-I eth0, -m mark), is answered.
func (p *pair) ping(t *testing.T, dst string, args ...string) bool {
	t.Helper()
	cmd := append([]string{"netns", "exec", p.dev, "ping", "-6", "-c", "1", "-W", "2"}, args...)
	out, err := exec.Command("ip", append(cmd, dst)...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "100% packet loss") && !strings.Contains(string(out), "not permitted") {
		t.Logf("ping %s %s: %v: %s", strings.Join(args, " "), dst, err, out)
	}
	return err == nil
}

// handles are the guard chain's rule handles, in order.
func (p *pair) handles(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", p.dev, "nft", "-a", "list", "chain", "inet", firewall.GuardTable, "output").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list chain: %v: %s", err, out)
	}
	var hs []string
	for _, m := range regexp.MustCompile(`# handle (\d+)`).FindAllStringSubmatch(string(out), -1) {
		hs = append(hs, m[1])
	}
	return strings.Join(hs, " ")
}

func (p *pair) table(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("ip", "netns", "exec", p.dev, "nft", "list", "tables").CombinedOutput()
	return string(out)
}

// inNamespace runs f on a thread in the device's namespace (sockets it
// opens stay there).
func (p *pair) inNamespace(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		ns, err := netns.GetFromName(p.dev)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = ns.Close() }()
		if err := netns.Set(ns); err != nil {
			t.Error(err)
			return
		}
		f()
	}()
	<-done
}

// dialBound connects a TCP socket bound to eth0 (SO_BINDTODEVICE) to
// dst:80 from the device's namespace.
func (p *pair) dialBound(t *testing.T, dst string) error {
	t.Helper()
	var err error
	p.inNamespace(t, func() {
		var fd int
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if err = unix.BindToDevice(fd, "eth0"); err != nil {
			return
		}
		tv := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
		err = unix.Connect(fd, &unix.SockaddrInet6{Port: 80, Addr: netip.MustParseAddr(dst).As16()})
	})
	return err
}

// The guard refuses IPv6 out of a physical interface, bound or not, but
// to direct destinations and endpoints, from the links' marked sockets,
// and on the link itself; IPv4 isn't its business; a removed table comes
// back with the next Apply; Close removes it.
func TestIPv6GuardRefusesWhatRoutingCantConfine(t *testing.T) {
	p := newPair(t)
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Fatal("the gateway doesn't answer without a guard: the test proves nothing")
	}
	g := p.guard(t)
	e := routetable.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: set(t, "2001:db8:d0::/48", "198.51.100.0/24")}
	ctx := context.Background()
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	expect := func(when string) {
		t.Helper()
		for _, c := range []struct {
			dst  string
			args []string
			want bool
		}{
			{foreign6, []string{"-I", "eth0"}, false},        // bound to the physical interface
			{foreign6, nil, false},                           // unbound, by main's routes (no route table here)
			{domestic6, []string{"-I", "eth0"}, true},        // direct
			{foreign6, []string{"-m", "29808"}, true},        // a link's marked socket
			{"ff02::1", []string{"-I", "eth0"}, true},        // the link itself (the gateway answers)
			{"2001:db8:1::1", []string{"-I", "eth0"}, false}, // the gateway's global address: not on-link trust
		} {
			if got := p.ping(t, c.dst, c.args...); got != c.want {
				t.Errorf("%s: ping %s %v answered %v, want %v", when, c.dst, c.args, got, c.want)
			}
		}
		// TCP is refused with a reset, at once.
		start := time.Now()
		if err := p.dialBound(t, foreign6); !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 2*time.Second {
			t.Errorf("%s: a TCP connect bound to eth0: %v after %v, want refused at once", when, err, time.Since(start))
		}
		out, err := exec.Command("ip", "netns", "exec", p.dev, "ping", "-4", "-c", "1", "-W", "2", "-I", "eth0", "192.0.2.1").CombinedOutput()
		if err != nil {
			t.Errorf("%s: IPv4 (the kill switch's, TP-048) refused: %v: %s", when, err, out)
		}
	}
	expect("applied")

	// The same again checks the table and leaves it; someone deleting it
	// is seen at once (Watch), and it comes back with the next Apply.
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithCancel(ctx)
	events, err := g.Watch(wctx)
	if err != nil {
		t.Fatal(err)
	}
	nft := func(args ...string) {
		t.Helper()
		p.nft(t, args...)
	}
	signalled := func(what string) {
		t.Helper()
		select {
		case <-events:
		case <-time.After(2 * time.Second):
			t.Errorf("Watch didn't signal %s", what)
		}
	}
	nft("add", "table", "inet", "someone-else") // another table: no signal
	nft("delete", "table", "inet", "someone-else")
	select {
	case <-events:
		t.Error("Watch signalled another table's changes")
	case <-time.After(500 * time.Millisecond):
	}
	nft("delete", "table", "inet", firewall.GuardTable)
	signalled("the table deleted")
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Fatal("still refused with the table deleted")
	}
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	signalled("its own Apply") // which finds it whole next time
	nft("flush", "ruleset")
	signalled("a flushed ruleset")
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	signalled("its own Apply")
	// A rule slipped in ahead of ours is seen, and the next Apply
	// rebuilds the table without it.
	nft("insert", "rule", "inet", firewall.GuardTable, "output", "accept")
	signalled("a rule inserted")
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	expect("re-applied after a rule was inserted")
	signalled("its own Apply")

	// Applying what is in place leaves the table as it is (the same rule
	// handles): whole compares what the kernel holds with what Apply put
	// there and finds them the same.
	handles := p.handles(t)
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	if got := p.handles(t); got != handles {
		t.Errorf("applying what was in place rebuilt the table: handles %s, were %s", got, handles)
	}

	// An element added to the set (a leak: the foreign site exempt) and
	// the reject rule replaced in place (the same rule count) are seen,
	// and the next Apply puts back exactly what it wants.
	nft("add", "element", "inet", firewall.GuardTable, "exempt6", "{ "+foreign6+" }")
	signalled("an element added")
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Fatal("the added element didn't open the foreign site: the test proves nothing")
	}
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	expect("re-applied after an element was added")
	signalled("its own Apply")
	last := strings.Fields(p.handles(t))
	nft("replace", "rule", "inet", firewall.GuardTable, "output", "handle", last[len(last)-1], "accept")
	signalled("a rule replaced")
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Fatal("the replaced rule didn't let the foreign site through: the test proves nothing")
	}
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	expect("re-applied after a rule was replaced")
	nft("delete", "element", "inet", firewall.GuardTable, "exempt6", "{ 2001:db8:d0::/48 }")
	signalled("an element deleted")
	cancel()
	for range events { // closes once ctx ends
	}
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	expect("re-applied after an element was deleted")

	// A successor (a restart after a crash) takes the table over.
	g2 := p.guard(t)
	if err := g2.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.table(t), firewall.GuardTable) {
		t.Errorf("a successor's Close left the table:\n%s", p.table(t))
	}
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.table(t), firewall.GuardTable) {
		t.Errorf("Close left the table:\n%s", p.table(t))
	}
	if !p.ping(t, foreign6, "-I", "eth0") {
		t.Error("refused after Close")
	}
	if err := g.Apply(ctx, e); err == nil {
		t.Error("Apply after Close succeeded")
	}
}

// The guard's table turned off from inside is seen, and the next Apply
// rebuilds it: made dormant (the kernel unhooks a dormant table's chains),
// or given a base chain of someone else's that marks packets as the
// links' before ours runs. A policy set on the guard's chain is seen too
// (it fails closed: every IPv6 packet meets a rule first).
func TestIPv6GuardRepairsItsTableTurnedOff(t *testing.T) {
	p := newPair(t)
	g := p.guard(t)
	e := routetable.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: set(t, "2001:db8:d0::/48")}
	ctx := context.Background()
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	events, err := g.Watch(wctx)
	if err != nil {
		t.Fatal(err)
	}
	// quiet takes the signals of the guard's own Apply.
	quiet := func() {
		for {
			select {
			case <-events:
			case <-time.After(500 * time.Millisecond):
				return
			}
		}
	}
	change := func(what string, args ...string) {
		t.Helper()
		quiet()
		p.nft(t, args...)
		select {
		case <-events:
		case <-time.After(2 * time.Second):
			t.Errorf("Watch didn't signal %s", what)
		}
	}
	leaks := func(what string) {
		t.Helper()
		if !p.ping(t, foreign6, "-I", "eth0") {
			t.Fatalf("%s didn't let a ping bound to eth0 out: the test proves nothing", what)
		}
	}
	repaired := func(what string) {
		t.Helper()
		if err := g.Apply(ctx, e); err != nil {
			t.Fatalf("re-apply after %s: %v", what, err)
		}
		if p.ping(t, foreign6, "-I", "eth0") {
			t.Errorf("re-applied after %s: a ping bound to eth0 still leaves", what)
		}
		if !p.ping(t, domestic6, "-I", "eth0") {
			t.Errorf("re-applied after %s: a direct site refused", what)
		}
	}

	change("the table made dormant", "add", "table", "inet", firewall.GuardTable, "{ flags dormant; }")
	leaks("a dormant table")
	repaired("the table was made dormant")

	change("a base chain added", "add", "chain", "inet", firewall.GuardTable, "pre", "{ type filter hook output priority 0; }")
	change("a rule in it", "add", "rule", "inet", firewall.GuardTable, "pre", "meta", "mark", "set", "0x7470")
	leaks("a chain setting the links' mark")
	repaired("a mark-setting chain was added")

	change("the chain's policy", "chain", "inet", firewall.GuardTable, "output", "{ policy drop; }")
	repaired("the chain's policy was changed")
}

// nft runs nft in the device's namespace.
func (p *pair) nft(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", append([]string{"netns", "exec", p.dev, "nft"}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("nft %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// A country-sized direct set (RU's IPv6: ~10k prefixes) goes into one
// transaction quickly, and the interval set matches by range.
func TestIPv6GuardTakesACountrySizedSet(t *testing.T) {
	p := newPair(t)
	var b lists.Builder
	for i := range 10088 {
		n := uint32(0x2a000000) + uint32(i)*2 // every other /32 from 2a00::
		_ = b.AddPrefix(netip.PrefixFrom(netip.AddrFrom16([16]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), 32))
	}
	_ = b.AddPrefix(netip.MustParsePrefix("ff00::/8")) // up to the last address: an interval with no end
	direct, _ := b.Build()
	g := p.guard(t)
	start := time.Now()
	if err := g.Apply(context.Background(), routetable.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: direct}); err != nil {
		t.Fatal(err)
	}
	t.Logf("applied %d ranges in %v", len(routetable.Exempt{Direct: direct}.Ranges6()), time.Since(start).Round(time.Millisecond))
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("took %v", took)
	}
	// A re-apply compares the whole set with the kernel's and changes
	// nothing.
	handles := p.handles(t)
	start = time.Now()
	if err := g.Apply(context.Background(), routetable.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: direct}); err != nil {
		t.Fatal(err)
	}
	t.Logf("checked them in %v", time.Since(start).Round(time.Millisecond))
	if got := p.handles(t); got != handles {
		t.Errorf("a re-apply of the same set rebuilt the table: handles %s, were %s", got, handles)
	}
	if !p.ping(t, "2a00:2::1", "-I", "eth0") {
		t.Error("a destination inside a direct /32 refused")
	}
	if p.ping(t, "2a00:1::1", "-I", "eth0") {
		t.Error("a destination between direct /32s answered")
	}
	if p.ping(t, foreign6, "-I", "eth0") {
		t.Error("a foreign destination answered")
	}
}

// sendICMPv6 sends one bare ICMPv6 message of type typ with the hop limit
// hops from a raw socket bound to eth0 in the device's namespace.
func (p *pair) sendICMPv6(t *testing.T, typ byte, hops int, dst string) {
	t.Helper()
	p.inNamespace(t, func() {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = unix.Close(fd) }()
		if err := errors.Join(unix.BindToDevice(fd, "eth0"),
			unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, hops),
			unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, hops)); err != nil {
			t.Error(err)
			return
		}
		msg := make([]byte, 24) // type, code, checksum (the kernel's), reserved, a target
		msg[0] = typ
		copy(msg[8:], netip.MustParseAddr(dst).AsSlice())
		// A refused send may fail here (EPERM) or be answered with an
		// ICMPv6 error: either way nothing leaves.
		_ = unix.Sendto(fd, msg, 0, &unix.SockaddrInet6{Addr: netip.MustParseAddr(dst).As16()})
	})
}

// gwCounted is how many ICMPv6 messages of type typ to foreign6 the
// gateway has received (the kernel's own neighbour discovery goes to
// other addresses): an observer on the far side of the link.
func (p *pair) gwCounted(t *testing.T, typ byte) int {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", p.gw, "nft", "list", "chain", "inet", "observe", fmt.Sprintf("t%d", typ)).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v: %s", err, out)
	}
	f := strings.Fields(string(out))
	for i := range f[:len(f)-1] {
		if f[i] == "packets" {
			n, _ := strconv.Atoi(f[i+1])
			return n
		}
	}
	t.Fatalf("no counter in:\n%s", out)
	return 0
}

// Neighbour discovery and MLD pass the guard only as the link-scoped
// messages they are: a neighbour solicitation with hop limit 255 reaches
// the gateway even to a global address, one with another hop limit
// doesn't; MLD only with hop limit 1.
func TestIPv6GuardPassesNeighbourDiscoveryOnlyOnTheLink(t *testing.T) {
	p := newPair(t)
	var rules strings.Builder
	rules.WriteString("table inet observe {\n")
	for _, typ := range []int{135, 131} {
		fmt.Fprintf(&rules, "chain t%d { type filter hook input priority 0; ip6 daddr %s icmpv6 type %d counter; }\n", typ, foreign6, typ)
	}
	rules.WriteString("}\n")
	cmd := exec.Command("ip", "netns", "exec", p.gw, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v: %s", err, out)
	}
	g := p.guard(t)
	if err := g.Apply(context.Background(), routetable.Exempt{TUN: "thinkpol0", Mark: 0x7470}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		typ  byte
		hops int
		dst  string
		want int // the gateway's count after it
	}{
		{135, 64, foreign6, 0},  // a "neighbour solicitation" routed like any packet: refused
		{135, 255, foreign6, 1}, // the real thing: passes
		{131, 64, foreign6, 0},  // MLD with a hop limit that could leave the link
		{131, 1, foreign6, 1},   // MLD as it is sent
	} {
		p.sendICMPv6(t, c.typ, c.hops, c.dst)
		deadline := time.Now().Add(2 * time.Second)
		got := p.gwCounted(t, c.typ)
		for got != c.want && time.Now().Before(deadline) && c.want > 0 {
			time.Sleep(50 * time.Millisecond)
			got = p.gwCounted(t, c.typ)
		}
		if c.want == 0 {
			time.Sleep(300 * time.Millisecond)
			got = p.gwCounted(t, c.typ)
		}
		if got != c.want {
			t.Errorf("type %d, hop limit %d: the gateway counted %d, want %d", c.typ, c.hops, got, c.want)
		}
	}
}

func set(t *testing.T, prefixes ...string) *lists.Set {
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
