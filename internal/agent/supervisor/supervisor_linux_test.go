//go:build linux && !android

package supervisor_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// The test binary doubles as a worker and as a supervisor in a process of
// its own, chosen by the environment.
const (
	envWorker     = "SUPERVISOR_TEST_WORKER"     // set: this process is a worker
	envCrash      = "SUPERVISOR_TEST_CRASH"      // a space id whose worker fails once ready
	envProbe      = "SUPERVISOR_TEST_PROBE"      // set: workers report what they see and can do
	envTargets    = "SUPERVISOR_TEST_TARGETS"    // a file of addresses probing workers send to
	envSupervisor = "SUPERVISOR_TEST_SUPERVISOR" // space ids: this process is a supervisor
)

const probePort = 7000

func TestMain(m *testing.M) {
	switch {
	case os.Getenv(envWorker) != "":
		os.Exit(runTestWorker())
	case os.Getenv(envSupervisor) != "":
		os.Exit(runTestSupervisor())
	}
	os.Exit(m.Run())
}

func runTestWorker() int {
	var space string
	for i, a := range os.Args {
		if a == "-space" && i+1 < len(os.Args) {
			space = os.Args[i+1]
		}
	}
	id, err := netmap.ParseSpaceID(space)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	serve := worker.Idle
	switch {
	case os.Getenv(envCrash) == space:
		serve = func(context.Context, worker.Session) error { return errors.New("crashing on purpose") }
	case os.Getenv(envProbe) != "":
		serve = probe
	}
	if err := worker.Run(ctx, id, serve); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// probe runs in a sandboxed worker: it reports what the worker sees and can
// do, listens for datagrams and reports them, and tries to reach every
// target address, as a compromised worker would.
func probe(ctx context.Context, s worker.Session) error {
	say := func(format string, args ...any) { fmt.Fprintf(os.Stderr, "probe "+format+"\n", args...) }

	var links []string
	if ls, err := dump(netlink.LinkList); err == nil {
		for _, l := range ls {
			links = append(links, l.Attrs().Name)
		}
	}
	slices.Sort(links)
	var sysfs []string
	if es, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range es {
			sysfs = append(sysfs, e.Name())
		}
	}
	var procs []string
	if es, err := os.ReadDir("/proc"); err == nil {
		for _, e := range es {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				procs = append(procs, e.Name())
			}
		}
	}
	var run []string
	if es, err := os.ReadDir("/run"); err == nil {
		for _, e := range es {
			run = append(run, e.Name())
		}
	}
	ns := func(kind string) string { l, _ := os.Readlink("/proc/self/ns/" + kind); return l }
	say("view links=%s sysfs=%s procs=%s run=%s netns=%s pidns=%s mntns=%s",
		strings.Join(links, ","), strings.Join(sysfs, ","), strings.Join(procs, ","), strings.Join(run, ","),
		ns("net"), ns("pid"), ns("mnt"))

	// What the data plane needs.
	can := func(what string, err error) {
		if err != nil {
			say("cannot %s: %v", what, err)
		} else {
			say("can %s", what)
		}
	}
	dev, err := tun.CreateTUN("tp-probe", 1420)
	if err == nil {
		var l netlink.Link
		if l, err = netlink.LinkByName("tp-probe"); err == nil {
			err = netlink.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(100, 64, 0, 1), Mask: net.CIDRMask(10, 32)}})
		}
		_ = dev.Close()
	}
	can("tun", err)
	dns, err := net.ListenPacket("udp", ":53")
	if err == nil {
		_ = dns.Close()
	}
	can("bind53", err)
	// What it must not do.
	raw, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err == nil {
		_ = unix.Close(raw)
	}
	can("raw", err)
	// NET_ADMIN opens the namespace's own net sysctls, nothing else.
	can("netsysctl", os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
	hostname, _ := os.ReadFile("/proc/sys/kernel/hostname")
	can("sysctl", os.WriteFile("/proc/sys/kernel/hostname", hostname, 0))
	can("mount", unix.Mount("tmpfs", "/tmp", "tmpfs", 0, ""))
	can("setuid", syscall.Setuid(0))

	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", probePort))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			say("got %s %s", from.(*net.UDPAddr).AddrPort().Addr().Unmap(), buf[:n])
		}
	}()
	say("listening")

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		var targets []netip.Addr
		if path := os.Getenv(envTargets); path != "" {
			b, _ := os.ReadFile(path)
			for _, t := range strings.Fields(string(b)) {
				if a, err := netip.ParseAddr(t); err == nil {
					targets = append(targets, a)
				}
			}
		}
		for _, a := range targets {
			_, _ = pc.WriteTo([]byte("space="+s.Space.String()), net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, probePort)))
		}
	}
}

// runTestSupervisor runs a supervisor for the space ids in envSupervisor,
// prints its workers' pids once all are ready, and runs until killed.
func runTestSupervisor() int {
	var ids []netmap.SpaceID
	for _, s := range strings.Split(os.Getenv(envSupervisor), ",") {
		id, err := netmap.ParseSpaceID(s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		ids = append(ids, id)
	}
	s, err := supervisor.New(options(nil))
	if err == nil {
		err = s.SetSpaces(ids)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		ws := s.Workers()
		var pids []string
		for _, w := range ws {
			if w.Ready {
				pids = append(pids, strconv.Itoa(w.PID))
			}
		}
		if len(pids) == len(ids) {
			fmt.Println("ready", strings.Join(pids, " "))
			select {}
		}
	}
	fmt.Fprintln(os.Stderr, "workers not ready")
	return 1
}

func options(env []string) supervisor.Options {
	return supervisor.Options{
		// The default command: this test binary, run again as `worker`.
		Env:          append([]string{envWorker + "=1"}, env...),
		Backoff:      supervisor.Backoff{Initial: 50 * time.Millisecond, Max: 400 * time.Millisecond, ResetAfter: 10 * time.Second},
		ReadyTimeout: 10 * time.Second,
		StopTimeout:  3 * time.Second,
	}
}

func needsLab(t *testing.T) {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
}

func start(t *testing.T, opts supervisor.Options, spaces ...netmap.SpaceID) *supervisor.Supervisor {
	t.Helper()
	s, err := supervisor.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := s.SetSpaces(spaces); err != nil {
		t.Fatal(err)
	}
	waitReady(t, s, spaces...)
	return s
}

func eventually(t *testing.T, timeout time.Duration, what string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := cond()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func info(s *supervisor.Supervisor, space netmap.SpaceID) (supervisor.WorkerInfo, bool) {
	for _, w := range s.Workers() {
		if w.Space == space {
			return w, true
		}
	}
	return supervisor.WorkerInfo{}, false
}

// waitReady waits for every listed space's worker to be ready and returns
// them in that order.
func waitReady(t *testing.T, s *supervisor.Supervisor, spaces ...netmap.SpaceID) []supervisor.WorkerInfo {
	t.Helper()
	out := make([]supervisor.WorkerInfo, len(spaces))
	eventually(t, 20*time.Second, "workers ready", func() error {
		for i, id := range spaces {
			w, ok := info(s, id)
			if !ok || !w.Ready || w.PID == 0 {
				return fmt.Errorf("space %s: %+v, output %q", id, w, s.Output(id))
			}
			out[i] = w
		}
		return nil
	})
	return out
}

// probeLines returns a worker's "probe ..." lines (without the prefix).
func probeLines(s *supervisor.Supervisor, space netmap.SpaceID) []string {
	var out []string
	for _, l := range s.Output(space) {
		if rest, ok := strings.CutPrefix(l, "probe "); ok {
			out = append(out, rest)
		}
	}
	return out
}

// view waits for a worker's probe to finish and parses its last "view"
// line.
func view(t *testing.T, s *supervisor.Supervisor, space netmap.SpaceID) map[string]string {
	t.Helper()
	var line string
	eventually(t, 10*time.Second, "worker's probe", func() error {
		line = ""
		listening := false
		for _, l := range probeLines(s, space) {
			if rest, ok := strings.CutPrefix(l, "view "); ok {
				line, listening = rest, false
			}
			listening = listening || l == "listening"
		}
		if line == "" || !listening {
			return fmt.Errorf("probe not done: %q", s.Output(space))
		}
		return nil
	})
	out := map[string]string{}
	for _, f := range strings.Fields(line) {
		k, v, _ := strings.Cut(f, "=")
		out[k] = v
	}
	return out
}

func status(t *testing.T, pid int) map[string]string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// dump runs a netlink dump again while a concurrent change interrupts it,
// as when namespaces and their veths are going away.
func dump[T any](list func() ([]T, error)) ([]T, error) {
	for {
		out, err := list()
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return out, err
		}
	}
}

func alive(pid int) bool { return unix.Kill(pid, 0) == nil }

func spaceLinks(t *testing.T) []string {
	t.Helper()
	links, err := dump(netlink.LinkList)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range links {
		if strings.HasPrefix(l.Attrs().Name, supervisor.LinkPrefix) {
			out = append(out, l.Attrs().Name)
		}
	}
	return out
}

func hasTable(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command("nft", "list", "tables").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list tables: %v: %s", err, out)
	}
	return strings.Contains(string(out), "table inet "+supervisor.TableName)
}

// freshNamespace returns the interfaces a new network namespace has, as
// netlink and sysfs list them, with veth0 added: lo, plus the fallback
// devices of the tunnel drivers loaded, which every namespace gets its own
// of.
func freshNamespace(t *testing.T) (links, sysfs string) {
	t.Helper()
	name := "tp-fresh-" + strconv.Itoa(os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	defer func() { _ = exec.Command("ip", "netns", "del", name).Run() }()
	list := func(args ...string) string {
		out, err := exec.Command("ip", append([]string{"netns", "exec", name}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		names := append(strings.Fields(string(out)), "veth0")
		slices.Sort(names)
		return strings.Join(names, ",")
	}
	return list("sh", "-c", "ip -o link show | cut -d: -f2 | cut -d@ -f1"), list("ls", "/sys/class/net")
}

const capsKept = 1<<unix.CAP_NET_ADMIN | 1<<unix.CAP_NET_BIND_SERVICE

func TestWorkersAreSandboxed(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s := start(t, options([]string{envProbe + "=1"}), a, b)
	ws := waitReady(t, s, a, b)
	if ws[0].UID == ws[1].UID {
		t.Fatalf("both workers run as %d", ws[0].UID)
	}
	own := func(kind string) string { l, _ := os.Readlink("/proc/self/ns/" + kind); return l }
	links, sysfs := freshNamespace(t)
	seen := map[string]bool{}
	for i, id := range []netmap.SpaceID{a, b} {
		w := ws[i]
		st := status(t, w.PID)
		uid := strconv.Itoa(int(w.UID))
		if st["Uid"] != strings.Join([]string{uid, uid, uid, uid}, "\t") || st["Gid"] != strings.Join([]string{uid, uid, uid, uid}, "\t") {
			t.Errorf("space %d runs as uid %q gid %q, want %s", i, st["Uid"], st["Gid"], uid)
		}
		for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
			if got, _ := strconv.ParseUint(st[k], 16, 64); got != capsKept {
				t.Errorf("space %d: %s %s, want %x", i, k, st[k], capsKept)
			}
		}
		if st["CapInh"] != "0000000000000000" || st["CapAmb"] != "0000000000000000" || st["NoNewPrivs"] != "1" {
			t.Errorf("space %d: CapInh %s CapAmb %s NoNewPrivs %s", i, st["CapInh"], st["CapAmb"], st["NoNewPrivs"])
		}

		v := view(t, s, id)
		if v["links"] != links || v["sysfs"] != sysfs {
			t.Errorf("space %d sees interfaces %q (netlink) and %q (sysfs), want what a new namespace has (%q, %q) and veth0",
				i, v["links"], v["sysfs"], links, sysfs)
		}
		if v["procs"] != "1" {
			t.Errorf("space %d sees processes %q, want only itself", i, v["procs"])
		}
		if v["run"] != "thinkpol" {
			t.Errorf("space %d sees /run %q, want only its own thinkpol", i, v["run"])
		}
		for _, kind := range []string{"net", "pid", "mnt"} {
			got := v[kind+"ns"]
			if got == "" || got == own(kind) || seen[got] {
				t.Errorf("space %d: %s namespace %q shared (root's is %q)", i, kind, got, own(kind))
			}
			seen[got] = true
		}
		lines := strings.Join(probeLines(s, id), "\n")
		for _, want := range []string{"can tun", "can bind53", "can netsysctl", "cannot raw", "cannot sysctl", "cannot mount", "cannot setuid"} {
			if !strings.Contains(lines, want) {
				t.Errorf("space %d: no %q in\n%s", i, want, lines)
			}
		}
	}
}

// udpSink collects the datagrams a socket receives.
type udpSink struct {
	mu  sync.Mutex
	got []string
}

func listen(t *testing.T) *udpSink {
	t.Helper()
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", probePort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	sink := &udpSink{}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			sink.mu.Lock()
			sink.got = append(sink.got, fmt.Sprintf("%s %s", from, buf[:n]))
			sink.mu.Unlock()
		}
	}()
	return sink
}

func (u *udpSink) received() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.got)
}

func send(t *testing.T, to netip.Addr, payload string) {
	t.Helper()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, probePort)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte(payload))
}

// waitGot sends payload to a worker's space addresses until the worker
// reports it got it on each: the veth carries packets from the root
// namespace.
func waitGot(t *testing.T, s *supervisor.Supervisor, w supervisor.WorkerInfo, payload string) {
	t.Helper()
	for _, p := range w.SpaceAddrs {
		eventually(t, 10*time.Second, "datagram from the root namespace to "+p.Addr().String(), func() error {
			send(t, p.Addr(), payload+"@"+p.Addr().String())
			for _, l := range probeLines(s, w.Space) {
				if strings.HasPrefix(l, "got ") && strings.HasSuffix(l, " "+payload+"@"+p.Addr().String()) {
					return nil
				}
			}
			return errors.New("not received")
		})
	}
}

func nodeAddrs(t *testing.T) []netip.Addr {
	t.Helper()
	addrs, err := dump(func() ([]netlink.Addr, error) { return netlink.AddrList(nil, netlink.FAMILY_ALL) })
	if err != nil {
		t.Fatal(err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		ip, _ := netip.AddrFromSlice(a.IP)
		ip = ip.Unmap()
		if ip.IsGlobalUnicast() && !strings.HasPrefix(a.Label, supervisor.LinkPrefix) {
			out = append(out, ip)
		}
	}
	return out
}

// TestNoPacketCrossesSpaces has every worker send to the other space, to
// both veths' root ends and to the node's own addresses, as a compromised
// worker would; nothing may arrive, while the root namespace reaches each
// space fine.
func TestNoPacketCrossesSpaces(t *testing.T) {
	needsLab(t)
	// As on a server, which relays and exits: without the supervisor's
	// table, the root namespace would forward between spaces.
	for _, key := range []string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"} {
		was, err := os.ReadFile("/proc/sys/" + key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("/proc/sys/"+key, []byte("1"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile("/proc/sys/"+key, was, 0) })
	}
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	root := listen(t)
	// The workers read their targets from a file they can read after
	// dropping privileges, written once their addresses are known.
	dir, err := os.MkdirTemp("", "targets")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := dir + "/targets"
	s := start(t, options([]string{envProbe + "=1", envTargets + "=" + file}), a, b)
	ws := waitReady(t, s, a, b)
	var targets []string
	for _, ad := range nodeAddrs(t) {
		targets = append(targets, ad.String())
	}
	for _, w := range ws {
		for _, p := range append(slices.Clone(w.RootAddrs), w.SpaceAddrs...) {
			targets = append(targets, p.Addr().String())
		}
	}
	if err := os.WriteFile(file, []byte(strings.Join(targets, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	for i, w := range ws {
		waitGot(t, s, w, fmt.Sprintf("root-%d", i))
	}
	// The workers have been sending all along; give them a little longer.
	time.Sleep(2 * time.Second)
	if got := root.received(); len(got) > 0 {
		t.Errorf("the root namespace received %d datagrams from spaces, the first %q", len(got), got[0])
	}
	for i, id := range []netmap.SpaceID{a, b} {
		var crossed []string
		for _, l := range probeLines(s, id) {
			// A worker's own datagrams to its own address don't count.
			if strings.HasPrefix(l, "got ") && strings.Contains(l, "space=") && !strings.HasSuffix(l, "space="+id.String()) {
				crossed = append(crossed, l)
			}
		}
		if len(crossed) > 0 {
			t.Errorf("space %d received %d datagrams from another space, the first %q", i, len(crossed), crossed[0])
		}
	}
}

func TestKilledWorkerRestartsAlone(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s := start(t, options([]string{envProbe + "=1"}), a, b)
	ws := waitReady(t, s, a, b)
	bView := view(t, s, b)
	bLink, err := netlink.LinkByName(ws[1].Link)
	if err != nil {
		t.Fatal(err)
	}
	waitGot(t, s, ws[1], "before")

	if err := unix.Kill(ws[0].PID, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "the killed worker back", func() error {
		w, _ := info(s, a)
		if !w.Ready || w.PID == ws[0].PID || w.Starts != 2 {
			return fmt.Errorf("%+v", w)
		}
		return nil
	})
	if w, _ := info(s, a); !strings.Contains(w.LastExit, "killed") {
		t.Errorf("last exit %q, want it killed", w.LastExit)
	}
	if w, _ := info(s, a); view(t, s, a)["netns"] == "" || w.Link != ws[0].Link {
		t.Errorf("restarted worker: %+v", w)
	}

	w, _ := info(s, b)
	if w.PID != ws[1].PID || w.Starts != 1 || !w.Ready {
		t.Fatalf("the other worker was touched: %+v, was %+v", w, ws[1])
	}
	if v := view(t, s, b); v["netns"] != bView["netns"] {
		t.Fatalf("the other worker's namespace changed: %s, was %s", v["netns"], bView["netns"])
	}
	l, err := netlink.LinkByName(w.Link)
	if err != nil || l.Attrs().Index != bLink.Attrs().Index {
		t.Fatalf("the other worker's veth changed: %v", err)
	}
	waitGot(t, s, w, "after")
}

func TestCrashingWorkerBacksOff(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s, err := supervisor.New(options([]string{envCrash + "=" + a.String()}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.SetSpaces([]netmap.SpaceID{a, b}); err != nil {
		t.Fatal(err)
	}
	bw := waitReady(t, s, b)[0]
	began := time.Now()
	eventually(t, 20*time.Second, "four crashes", func() error {
		if w, _ := info(s, a); w.Starts < 4 {
			return fmt.Errorf("%d starts", w.Starts)
		}
		return nil
	})
	// Delays of 50, 100 and 200 ms come before the fourth start.
	if took := time.Since(began); took < 350*time.Millisecond {
		t.Errorf("four starts in %v: no backoff", took)
	}
	time.Sleep(2 * time.Second)
	// From the fifth start on, each waits 400 ms (plus the start itself).
	w, _ := info(s, a)
	if limit := 4 + int(time.Since(began)/(400*time.Millisecond)) + 1; w.Starts > limit {
		t.Errorf("%d starts in %v, at most %d with backoff", w.Starts, time.Since(began), limit)
	}
	if !strings.Contains(strings.Join(s.Output(a), "\n"), "crashing on purpose") {
		t.Errorf("worker output not kept: %q", s.Output(a))
	}
	if !strings.Contains(w.LastExit, "exit status 1") {
		t.Errorf("last exit %q", w.LastExit)
	}
	if got, _ := info(s, b); got.PID != bw.PID || got.Starts != 1 || !got.Ready {
		t.Fatalf("the healthy worker was touched: %+v, was %+v", got, bw)
	}
}

// netNamespaces lists every network namespace something on the node still
// holds: a process, a thread, an open descriptor or a mount.
func netNamespaces(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	add := func(link string) {
		if l, err := os.Readlink(link); err == nil && strings.HasPrefix(l, "net:[") {
			out[l] = true
		}
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		add("/proc/" + p.Name() + "/ns/net")
		tasks, _ := os.ReadDir("/proc/" + p.Name() + "/task")
		for _, task := range tasks {
			add("/proc/" + p.Name() + "/task/" + task.Name() + "/ns/net")
		}
		fds, _ := os.ReadDir("/proc/" + p.Name() + "/fd")
		for _, fd := range fds {
			add("/proc/" + p.Name() + "/fd/" + fd.Name())
		}
	}
	mounts, _ := os.ReadFile("/proc/self/mountinfo")
	for _, line := range strings.Split(string(mounts), "\n") {
		if f := strings.Fields(line); len(f) > 3 && strings.HasPrefix(f[3], "net:[") {
			out[f[3]] = true
		}
	}
	return out
}

func TestCloseRemovesEverything(t *testing.T) {
	needsLab(t)
	linksBefore, err := dump(netlink.LinkList)
	if err != nil {
		t.Fatal(err)
	}
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s, err := supervisor.New(options([]string{envProbe + "=1"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSpaces([]netmap.SpaceID{a, b}); err != nil {
		t.Fatal(err)
	}
	ws := waitReady(t, s, a, b)
	spaceNS := []string{view(t, s, a)["netns"], view(t, s, b)["netns"]}
	if len(spaceLinks(t)) != 2 || !hasTable(t) {
		t.Fatalf("running: links %q, table %v", spaceLinks(t), hasTable(t))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	for _, w := range ws {
		if alive(w.PID) {
			t.Errorf("worker %d still running", w.PID)
		}
	}
	held := netNamespaces(t)
	for _, ns := range spaceNS {
		if held[ns] {
			t.Errorf("namespace %s is still held", ns)
		}
	}
	linksAfter, err := dump(netlink.LinkList)
	if err != nil {
		t.Fatal(err)
	}
	names := func(ls []netlink.Link) []string {
		var out []string
		for _, l := range ls {
			out = append(out, l.Attrs().Name)
		}
		slices.Sort(out)
		return out
	}
	if !slices.Equal(names(linksBefore), names(linksAfter)) {
		t.Errorf("links %q after Close, %q before", names(linksAfter), names(linksBefore))
	}
	if hasTable(t) {
		t.Error("nftables table left behind")
	}
	routes, err := dump(func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Protocol: netcfg.OwnerSupervisor.RouteProtocol()}, netlink.RT_FILTER_PROTOCOL)
	})
	if err != nil || len(routes) > 0 {
		t.Errorf("supervisor routes left in the root namespace: %v, %v", routes, err)
	}
	if out, _ := exec.Command("ip", "netns", "list").CombinedOutput(); len(strings.TrimSpace(string(out))) > 0 {
		t.Errorf("named namespaces: %s", out)
	}
	if err := s.SetSpaces([]netmap.SpaceID{a}); err == nil {
		t.Error("a closed supervisor took spaces")
	}
}

// TestSupervisorDeathKillsWorkers kills a supervisor without warning: its
// workers die with it (no orphans), their namespaces and veths go with
// them, and the next supervisor starts clean.
func TestSupervisorDeathKillsWorkers(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), envSupervisor+"="+a.String()+","+b.String())
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var pids []int
	select {
	case line := <-lines:
		for _, f := range strings.Fields(strings.TrimPrefix(line, "ready")) {
			pid, err := strconv.Atoi(f)
			if err != nil {
				t.Fatalf("supervisor said %q", line)
			}
			pids = append(pids, pid)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("supervisor's workers not ready")
	}
	if len(pids) != 2 || len(spaceLinks(t)) != 2 {
		t.Fatalf("workers %v, links %q", pids, spaceLinks(t))
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	eventually(t, 10*time.Second, "workers gone with their supervisor", func() error {
		for _, pid := range pids {
			if alive(pid) {
				return fmt.Errorf("worker %d alive", pid)
			}
		}
		return nil
	})
	eventually(t, 10*time.Second, "veths gone with their namespaces", func() error {
		if l := spaceLinks(t); len(l) > 0 {
			return fmt.Errorf("links %q", l)
		}
		return nil
	})
	// The dead supervisor's table is still there; the next one replaces it
	// and serves.
	start(t, options(nil), a)
}

func TestOneSupervisorPerNode(t *testing.T) {
	needsLab(t)
	start(t, options(nil))
	if s, err := supervisor.New(options(nil)); !errors.Is(err, netcfg.ErrBusy) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatalf("second supervisor: %v, want ErrBusy", err)
	}
	if !hasTable(t) {
		t.Fatal("the failed second supervisor removed the first one's table")
	}
}

func TestSetSpacesAddsAndRemoves(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s := start(t, options(nil), a)
	wa := waitReady(t, s, a)[0]
	if err := s.SetSpaces([]netmap.SpaceID{a, b}); err != nil {
		t.Fatal(err)
	}
	ws := waitReady(t, s, a, b)
	if ws[0].PID != wa.PID || ws[0].Starts != 1 {
		t.Fatalf("adding a space touched another: %+v, was %+v", ws[0], wa)
	}
	if err := s.SetSpaces([]netmap.SpaceID{b}); err != nil {
		t.Fatal(err)
	}
	if alive(wa.PID) {
		t.Error("removed space's worker still running")
	}
	if _, err := netlink.LinkByName(wa.Link); err == nil {
		t.Errorf("removed space's veth %s still there", wa.Link)
	}
	if w, _ := info(s, b); w.PID != ws[1].PID || len(s.Workers()) != 1 {
		t.Fatalf("workers after removal: %+v", s.Workers())
	}
	if err := s.SetSpaces([]netmap.SpaceID{b, b}); err == nil {
		t.Error("a space listed twice was taken")
	}
	// The freed slot is reused.
	c := netmap.NewSpaceID()
	if err := s.SetSpaces([]netmap.SpaceID{b, c}); err != nil {
		t.Fatal(err)
	}
	if wc := waitReady(t, s, c)[0]; wc.Link != wa.Link {
		t.Errorf("new space got %s, want the freed %s", wc.Link, wa.Link)
	}
}

// TestThinkpolWorkerCommand runs the real binary's hidden worker command,
// built from this checkout into every lab node.
func TestThinkpolWorkerCommand(t *testing.T) {
	needsLab(t)
	const bin = "/opt/thinkpol/bin/thinkpol"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("no %s: %v", bin, err)
	}
	a := netmap.NewSpaceID()
	opts := options(nil)
	opts.Command, opts.Env = []string{bin, "worker"}, nil
	events := logring.New(1 << 16)
	opts.Log = slog.New(slog.NewTextHandler(events, nil))
	s := start(t, opts, a)
	w := waitReady(t, s, a)[0]
	if st := status(t, w.PID); !strings.HasPrefix(st["Uid"], strconv.Itoa(int(w.UID))+"\t") || st["NoNewPrivs"] != "1" {
		t.Fatalf("thinkpol worker runs as %q, no_new_privs %q", st["Uid"], st["NoNewPrivs"])
	}
	if err := s.SetSpaces(nil); err != nil {
		t.Fatal(err)
	}
	if alive(w.PID) {
		t.Fatal("still running after Stop")
	}
	if log := events.String(); !strings.Contains(log, `msg="worker stopped" space=`+a.String()) || !strings.Contains(log, "err=<nil>") {
		t.Fatalf("no clean stop in the supervisor's log:\n%s", log)
	}
}
