//go:build linux && !android

package supervisor_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
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
	envCrash      = "SUPERVISOR_TEST_CRASH"      // the worker fails once ready
	envProbe      = "SUPERVISOR_TEST_PROBE"      // set: the worker reports what it sees and can do
	envTargets    = "SUPERVISOR_TEST_TARGETS"    // a file of addresses a probing worker sends to
	envSupervisor = "SUPERVISOR_TEST_SUPERVISOR" // space ids: this process is a supervisor
)

const probePort = 7000

func TestMain(m *testing.M) {
	switch {
	case os.Getenv("SUPERVISOR_TEST_ESCAPE") != "":
		os.Exit(runEscapeControl())
	case os.Getenv("SUPERVISOR_TEST_BAD_KIND") != "":
		os.Exit(runBadKindWorker())
	case os.Getenv("SUPERVISOR_TEST_DEAF") != "":
		os.Exit(runDeafWorker())
	case os.Getenv(envWorker) != "":
		os.Exit(runTestWorker())
	case os.Getenv(envSupervisor) != "":
		os.Exit(runTestSupervisor())
	case os.Getenv(envSharedSupervisor) != "":
		os.Exit(runSharedSupervisor())
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
	case os.Getenv(envCrash) != "":
		serve = func(context.Context, worker.Session) error { return errors.New("crashing on purpose") }
	case os.Getenv("SUPERVISOR_TEST_IGNORE_STOP") != "":
		serve = func(context.Context, worker.Session) error { select {} } // never returns: must be killed
	case os.Getenv(envProbe) != "":
		serve = probe
	case os.Getenv(envShared) != "":
		serve = sharedServe
	}
	if err := worker.Run(ctx, id, serve); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// probe runs in a sandboxed worker: it reports what the worker sees and can
// do, tries the namespace escape, listens for datagrams and reports them, and
// sends to every target address as a compromised worker would.
func probe(ctx context.Context, s worker.Session) error {
	say := func(format string, args ...any) { fmt.Fprintf(os.Stderr, "probe "+format+"\n", args...) }

	// The worker has no /proc: it reports what it can see over netlink and
	// through syscalls; the test checks its namespaces and credentials from
	// the outside via /proc/<pid>.
	var links []string
	if ls, err := dump(netlink.LinkList); err == nil {
		for _, l := range ls {
			links = append(links, l.Attrs().Name)
		}
	}
	slices.Sort(links)
	say("view links=%s root=%s caps=%016x", strings.Join(links, ","), dirList("/"), effectiveCaps())

	// A NET_ADMIN operation in the worker's own namespace: add and remove a
	// dummy link.
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tp-probe0"}}
	if err := netlink.LinkAdd(dummy); err != nil {
		say("cannot netadmin: %v", err)
	} else {
		say("can netadmin")
		_ = netlink.LinkDel(dummy)
	}
	// SYS_ADMIN was dropped: a mount must fail.
	if err := unix.Mount("tmpfs", "/tmp", "tmpfs", 0, ""); err == nil {
		say("can mount")
	} else {
		say("cannot mount: %v", err)
	}

	if err := escapeAttempt("tp-escape-w"); err != nil {
		say("escape blocked: %v", err)
	} else {
		say("escape ok")
	}

	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", probePort))
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = pc.Close() }()
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

	// Config arrives over the control channel (the worker can't read a host
	// file after pivot_root); the latest config wins. Report a hash so the
	// test can confirm exactly what the worker received, and parse any targets
	// to send to.
	var tmu sync.Mutex
	var tgts []target
	go func() {
		for cfg := range s.Config {
			if bytes.Contains(cfg, []byte(dropSpaceTable)) {
				// As a compromised worker would: its namespace's table
				// (which SNATs any source to the transit address) is its
				// own to delete; only the root namespace's stands.
				err := deleteSpaceTable()
				say("deleted the space table: %v", err)
			}
			parsed := parseTargets(cfg)
			tmu.Lock()
			tgts = parsed
			tmu.Unlock()
			say("config sha256=%x len=%d targets=%d", sha256.Sum256(cfg), len(cfg), len(parsed))
		}
	}()
	say("listening")

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	seen := map[[32]byte]bool{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		if s.Seeds != nil {
			for _, sha := range s.Seeds.Hashes() {
				if !seen[sha] {
					seen[sha] = true
					say("seed sha256=%x", sha)
				}
			}
		}
		tmu.Lock()
		current := tgts
		tmu.Unlock()
		for _, target := range current {
			payload := "space=" + s.Space.String()
			if target.tag != "" {
				payload += "#" + target.tag
			}
			switch {
			case target.icmp != nil && len(s.Addrs) > 0:
				target.icmp.send(s.Addrs[0].Addr())
			case target.spoof.IsValid():
				spoofedSend(target.addr, target.spoof, payload)
			default:
				_, _ = pc.WriteTo([]byte(payload), net.UDPAddrFromAddrPort(netip.AddrPortFrom(target.addr, target.port)))
			}
		}
	}
}

// dropSpaceTable in a probe's config makes it delete its namespace's
// egress table before sending.
const dropSpaceTable = "drop-space-table"

func deleteSpaceTable() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: supervisor.SpaceTableName})
	return c.Flush()
}

// effectiveCaps returns the worker's effective capability set via capget.
func effectiveCaps() uint64 {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: int32(os.Getpid())}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0
	}
	return uint64(data[0].Effective) | uint64(data[1].Effective)<<32
}

type target struct {
	icmp  *icmpError // when set, send this forged ICMP error instead
	addr  netip.Addr
	port  uint16     // probePort unless the target names one
	spoof netip.Addr // when valid, send with this source address (to probePort)
	tag   string     // appended to the payload after a '#'
}

// parseTargets reads a probe's targets, one per field:
// <address>[@<spoofed source>][#<tag>] or <address:port>[#<tag>].
func parseTargets(config []byte) []target {
	var out []target
	for _, line := range strings.Fields(string(config)) {
		if e, ok := parseICMPError(line); ok {
			out = append(out, target{icmp: e})
			continue
		}
		line, tag, _ := strings.Cut(line, "#")
		dst, spoof, _ := strings.Cut(line, "@")
		t := target{port: probePort, tag: tag}
		if ap, err := netip.ParseAddrPort(dst); err == nil {
			t.addr, t.port = ap.Addr(), ap.Port()
		} else if a, err := netip.ParseAddr(dst); err == nil {
			t.addr = a
		} else {
			continue
		}
		if spoof != "" {
			t.spoof, _ = netip.ParseAddr(spoof)
		}
		out = append(out, t)
	}
	return out
}

// icmpError is a forged IPv4 ICMP error a probe sends from its transit
// address to dst, quoting a UDP packet inner, as a compromised worker would
// to interfere with a flow it doesn't own (conntrack takes an error as
// related to the flow its quote names).
type icmpError struct {
	dst                netip.Addr
	typ, code          byte
	mtu                uint16
	innerSrc, innerDst netip.AddrPort
}

// parseICMPError reads icmp/<dst>/<type>/<code>/<mtu>/<inner src>/<inner dst>.
func parseICMPError(field string) (*icmpError, bool) {
	parts := strings.Split(field, "/")
	if len(parts) != 7 || parts[0] != "icmp" {
		return nil, false
	}
	dst, err1 := netip.ParseAddr(parts[1])
	typ, err2 := strconv.Atoi(parts[2])
	code, err3 := strconv.Atoi(parts[3])
	mtu, err4 := strconv.Atoi(parts[4])
	src, err5 := netip.ParseAddrPort(parts[5])
	idst, err6 := netip.ParseAddrPort(parts[6])
	if errors.Join(err1, err2, err3, err4, err5, err6) != nil {
		return nil, false
	}
	return &icmpError{dst: dst, typ: byte(typ), code: byte(code), mtu: uint16(mtu), innerSrc: src, innerDst: idst}, true
}

func (e *icmpError) String() string {
	return fmt.Sprintf("icmp/%s/%d/%d/%d/%s/%s", e.dst, e.typ, e.code, e.mtu, e.innerSrc, e.innerDst)
}

func (e *icmpError) send(src netip.Addr) {
	inner := udp4Packet(e.innerSrc.Addr(), e.innerDst.Addr(), int(e.innerSrc.Port()), int(e.innerDst.Port()), []byte("quoted"))
	ipChecksum(inner[:20])
	msg := make([]byte, 8, 8+len(inner))
	msg[0], msg[1] = e.typ, e.code
	binary.BigEndian.PutUint16(msg[6:], e.mtu)
	msg = append(msg, inner...)
	binary.BigEndian.PutUint16(msg[2:], checksum(msg))
	pkt := make([]byte, 20, 20+len(msg))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(20+len(msg)))
	pkt[8], pkt[9] = 64, unix.IPPROTO_ICMP
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], e.dst.AsSlice())
	pkt = append(pkt, msg...)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(fd) }()
	_ = unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Addr: e.dst.As4()})
}

func ipChecksum(h []byte) {
	h[10], h[11] = 0, 0
	binary.BigEndian.PutUint16(h[10:], checksum(h))
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// spoofedSend sends a UDP datagram with a forged source address, to test
// anti-spoofing. Best-effort: it needs a raw socket, which the worker has in
// its own namespace.
func spoofedSend(dst, src netip.Addr, payload string) {
	if dst.Is4() {
		rawSend4(src, dst, payload)
	}
}

func dirList(path string) string {
	es, _ := os.ReadDir(path)
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// The worker has no /proc, so the test inspects it from the outside through
// /proc/<pid>; the supervisor owns the worker's user namespace, so this is
// permitted without CAP_SYS_PTRACE.

func procLink(t *testing.T, pid int, kind string) string {
	t.Helper()
	l, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, kind))
	if err != nil {
		t.Fatalf("read %d ns %s: %v", pid, kind, err)
	}
	return l
}

func procUIDMap(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/uid_map", pid))
	if err != nil {
		t.Fatalf("uid_map %d: %v", pid, err)
	}
	return strings.Join(strings.Fields(string(b)), "_")
}

// procLeakedFiles returns any open fd of pid that points to a real file path
// outside the worker's minimal root (its only allowed device nodes). The
// supervisor passes only the control and data sockets (via ExtraFiles) and Go
// marks everything else close-on-exec, so a leaked host-file fd would be a
// bug.
func procLeakedFiles(t *testing.T, pid int) []string {
	t.Helper()
	allowed := map[string]bool{"/dev/null": true, "/dev/zero": true, "/dev/urandom": true, "/dev/net/tun": true}
	es, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatalf("fds %d: %v", pid, err)
	}
	var leaked []string
	for _, e := range es {
		l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name()))
		switch {
		case err != nil, !strings.HasPrefix(l, "/"), l == "/", allowed[l]:
			continue
		case strings.HasPrefix(l, "/dev/"):
			continue
		case strings.Count(l, "/") == 1 && strings.Contains(l, "."):
			// A cgroup control file at the worker's cgroup-namespace root,
			// e.g. /cpu.max, which the Go runtime reads for GOMAXPROCS.
			continue
		}
		leaked = append(leaked, l)
	}
	return leaked
}

// rawSend4 sends an IPv4 UDP datagram with a chosen source address.
func rawSend4(src, dst netip.Addr, payload string) {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(s) }()
	pkt := udp4Packet(src, dst, probePort, probePort, []byte(payload))
	_ = unix.Sendto(s, pkt, 0, &unix.SockaddrInet4{Addr: dst.As4()})
}

func udp4Packet(src, dst netip.Addr, sport, dport int, payload []byte) []byte {
	nbo := func(b []byte, v uint16) { b[0], b[1] = byte(v>>8), byte(v) }
	udp := make([]byte, 8+len(payload))
	nbo(udp[0:], uint16(sport))
	nbo(udp[2:], uint16(dport))
	nbo(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	ip := make([]byte, 20)
	ip[0] = 0x45
	nbo(ip[2:], uint16(20+len(udp)))
	ip[8] = 64
	ip[9] = unix.IPPROTO_UDP
	copy(ip[12:16], src.AsSlice())
	copy(ip[16:20], dst.AsSlice())
	return append(ip, udp...)
}

// runEscapeControl mirrors a worker left in the initial user namespace: a new
// network namespace (no user namespace) with a veth whose peer is in the root
// namespace. It runs the escape op and prints the result, the negative control
// for TestNetnsidEscapeBlocked.
// runBadKindWorker is a worker that, after Ready, sends an unexpected message
// kind on its control socket; the supervisor must kill and restart it. It
// does not sandbox (the supervisor doesn't care how the worker misbehaves).
func runBadKindWorker() int {
	cf := os.NewFile(uintptr(ipc.ControlFD), "control")
	c, err := ipc.FromFile(cf)
	_ = cf.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := c.Receive(); err != nil { // Init
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := c.Send(ipc.Message{Kind: ipc.KindReady}); err != nil {
		return 1
	}
	if err := c.Send(ipc.Message{Kind: 222}); err != nil {
		return 1
	}
	_, _ = c.Receive() // block until the supervisor closes the socket
	return 0
}

// runDeafWorker is a worker that reports Ready and then never reads its
// control socket again.
func runDeafWorker() int {
	cf := os.NewFile(uintptr(ipc.ControlFD), "control")
	c, err := ipc.FromFile(cf)
	_ = cf.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := c.Receive(); err != nil { // Init
		return 1
	}
	if err := c.Send(ipc.Message{Kind: ipc.KindReady}); err != nil {
		return 1
	}
	time.Sleep(time.Hour) // alive, reading nothing
	return 0
}

// A worker that stops reading its control socket is killed once a control
// send has waited StopTimeout, and restarted; neither SetSpaces nor Close
// hangs on it.
func TestDeafWorkerHoldsNothingUp(t *testing.T) {
	needsLab(t)
	opts := options([]string{"SUPERVISOR_TEST_DEAF=1"})
	opts.StopTimeout = time.Second
	space := netmap.NewSpaceID()
	s, err := supervisor.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSpaces([]supervisor.Space{{ID: space, Config: []byte("first")}}); err != nil {
		t.Fatal(err)
	}
	waitReady(t, s, space)
	config := make([]byte, 60<<10)
	begin := time.Now()
	for i := 0; ; i++ {
		config[0], config[1] = byte(i), byte(i>>8)
		if err := s.SetSpaces([]supervisor.Space{{ID: space, Config: append([]byte(nil), config...)}}); err != nil {
			t.Fatal(err)
		}
		w, _ := info(s, space)
		if strings.Contains(w.LastExit, "sending config") && strings.Contains(w.LastExit, "timeout") {
			t.Logf("killed after %v: %s", time.Since(begin), w.LastExit)
			break
		}
		if w.LastExit != "" && !strings.Contains(w.LastExit, "timeout") {
			t.Fatalf("the worker ended otherwise: %s", w.LastExit)
		}
		if time.Since(begin) > 30*time.Second {
			t.Fatalf("still not killed: %+v", w)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitReady(t, s, space) // restarted
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * opts.StopTimeout):
		t.Fatal("Close hung on a deaf worker")
	}
}

func runEscapeControl() int {
	runtime.LockOSThread()
	rootns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = rootns.Close() }()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		fmt.Fprintln(os.Stderr, "unshare:", err)
		return 1
	}
	// Register an id for the root namespace in this new namespace, then try to
	// create a dummy there through it — the same operation a worker attempts,
	// but from the initial user namespace, where it is permitted.
	if err := netlink.SetNetNsIdByFd(int(rootns.Fd()), 0); err != nil {
		fmt.Fprintln(os.Stderr, "set nsid:", err)
		return 1
	}
	defer func() {
		if h, err := netlink.NewHandleAt(netns.NsHandle(rootns.Fd())); err == nil {
			if l, err := h.LinkByName("tp-escape-ctl"); err == nil {
				_ = h.LinkDel(l)
			}
			h.Close()
		}
	}()
	if err := createDummyInNetns(0, "tp-escape-ctl"); err != nil {
		fmt.Printf("escape blocked: %v\n", err)
	} else {
		fmt.Println("escape ok")
	}
	return 0
}

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
		err = s.SetSpaces(spacesOf(ids...))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		var pids []string
		for _, w := range s.Workers() {
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
		Env:          append([]string{envWorker + "=1"}, env...),
		Backoff:      supervisor.Backoff{Initial: 50 * time.Millisecond, Max: 400 * time.Millisecond, ResetAfter: 10 * time.Second},
		ReadyTimeout: 15 * time.Second,
		StopTimeout:  3 * time.Second,
		PidsMax:      512,
		MemoryMax:    256 << 20,
	}
}

func spacesOf(ids ...netmap.SpaceID) []supervisor.Space {
	out := make([]supervisor.Space, len(ids))
	for i, id := range ids {
		out[i] = supervisor.Space{ID: id}
	}
	return out
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
	if err := s.SetSpaces(spacesOf(spaces...)); err != nil {
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

func waitReady(t *testing.T, s *supervisor.Supervisor, spaces ...netmap.SpaceID) []supervisor.WorkerInfo {
	t.Helper()
	out := make([]supervisor.WorkerInfo, len(spaces))
	eventually(t, 25*time.Second, "workers ready", func() error {
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

func probeLines(s *supervisor.Supervisor, space netmap.SpaceID) []string {
	var out []string
	for _, l := range s.Output(space) {
		if rest, ok := strings.CutPrefix(l, "probe "); ok {
			out = append(out, rest)
		}
	}
	return out
}

// probeDone waits for a worker's probe to report, and returns its view fields
// and all its lines.
func probeDone(t *testing.T, s *supervisor.Supervisor, space netmap.SpaceID) (map[string]string, []string) {
	t.Helper()
	var view string
	var lines []string
	eventually(t, 15*time.Second, "worker's probe", func() error {
		view, lines = "", probeLines(s, space)
		listening := false
		for _, l := range lines {
			if rest, ok := strings.CutPrefix(l, "view "); ok {
				view = rest
			}
			listening = listening || l == "listening"
		}
		if view == "" || !listening {
			return fmt.Errorf("probe not done: %q", s.Output(space))
		}
		return nil
	})
	fields := map[string]string{}
	for _, f := range strings.Fields(view) {
		k, v, _ := strings.Cut(f, "=")
		fields[k] = v
	}
	return fields, lines
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

func hasTable(t *testing.T, name string) bool {
	t.Helper()
	out, err := exec.Command("nft", "list", "tables").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list tables: %v: %s", err, out)
	}
	return strings.Contains(string(out), name)
}

// dump runs a netlink dump again while a concurrent change interrupts it, as
// when namespaces and their veths are going away.
func dump[T any](list func() ([]T, error)) ([]T, error) {
	for {
		out, err := list()
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return out, err
		}
	}
}

// freshNamespace returns the interfaces a new network namespace has (lo plus
// the kernel's fallback tunnel devices), with veth0 added, as netlink lists
// them.
func freshNamespace(t *testing.T) string {
	t.Helper()
	name := "tp-fresh-" + strconv.Itoa(os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	defer func() { _ = exec.Command("ip", "netns", "del", name).Run() }()
	out, err := exec.Command("ip", "netns", "exec", name, "sh", "-c", "ip -o link show | cut -d: -f2 | cut -d@ -f1").CombinedOutput()
	if err != nil {
		t.Fatalf("list fresh namespace: %v: %s", err, out)
	}
	names := append(strings.Fields(string(out)), "veth0")
	slices.Sort(names)
	return strings.Join(names, ",")
}

const capsKept = uint64(1)<<unix.CAP_NET_ADMIN | uint64(1)<<unix.CAP_NET_RAW | uint64(1)<<unix.CAP_NET_BIND_SERVICE

func TestWorkersAreSandboxed(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s := start(t, options([]string{envProbe + "=1"}), a, b)
	ws := waitReady(t, s, a, b)
	if ws[0].UID == ws[1].UID {
		t.Fatalf("both workers map to host uid %d", ws[0].UID)
	}
	own := func(kind string) string { l, _ := os.Readlink("/proc/self/ns/" + kind); return l }
	wantLinks := freshNamespace(t)
	seen := map[string]bool{}
	for i, id := range []netmap.SpaceID{a, b} {
		v, lines := probeDone(t, s, id)
		w, _ := info(s, id)
		if w.Starts != 1 || !alive(w.PID) {
			t.Fatalf("space %d worker flapping: %+v\noutput:\n%s", i, w, strings.Join(s.Output(id), "\n"))
		}
		pid := w.PID

		// A user namespace mapping its root to the worker's host uid, owning
		// the worker's network namespace: the escape defence rests on it.
		if v["uidmap"] = procUIDMap(t, pid); v["uidmap"] != fmt.Sprintf("0_%d_1", w.UID) {
			t.Errorf("space %d uid_map %q, want 0 %d 1", i, v["uidmap"], w.UID)
		}
		if netnsOwnerOf(t, pid) != nsIno(t, fmt.Sprintf("/proc/%d/ns/user", pid)) {
			t.Errorf("space %d network namespace not owned by its own user namespace", i)
		}
		st := status(t, pid)
		if st["NoNewPrivs"] != "1" {
			t.Errorf("space %d NoNewPrivs %q", i, st["NoNewPrivs"])
		}
		// Only the network capabilities remain; SYS_ADMIN (used for the
		// mounts) is gone.
		for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
			if got, _ := strconv.ParseUint(st[k], 16, 64); got != capsKept {
				t.Errorf("space %d: %s %s, want %016x", i, k, st[k], capsKept)
			}
		}
		if st["CapInh"] != "0000000000000000" || st["CapAmb"] != "0000000000000000" {
			t.Errorf("space %d: CapInh %s CapAmb %s", i, st["CapInh"], st["CapAmb"])
		}
		// Supplementary groups cleared.
		if g := strings.TrimSpace(st["Groups"]); g != "" {
			t.Errorf("space %d: supplementary groups %q, want none", i, g)
		}
		if caps, _ := strconv.ParseUint(v["caps"], 16, 64); caps != capsKept {
			t.Errorf("space %d effective caps %q, want %016x", i, v["caps"], capsKept)
		}

		// A minimal root, its own interfaces, exactly its two sockets.
		if v["root"] != "dev,run,tmp" {
			t.Errorf("space %d root %q, want a minimal tmpfs without /proc or /sys", i, v["root"])
		}
		if v["links"] != wantLinks {
			t.Errorf("space %d interfaces %q, want %q", i, v["links"], wantLinks)
		}
		if leaked := procLeakedFiles(t, pid); len(leaked) > 0 {
			t.Errorf("space %d has leaked host-file fds: %q", i, leaked)
		}
		// Every namespace fresh and distinct from the root's and the other
		// worker's (a different IPC namespace means SysV shm isn't shared).
		for _, kind := range []string{"net", "pid", "mnt", "ipc", "user"} {
			got := procLink(t, pid, kind)
			if got == own(kind) || seen[kind+got] {
				t.Errorf("space %d: %s namespace %q shared (root's is %q)", i, kind, got, own(kind))
			}
			seen[kind+got] = true
		}
		// It can do NET_ADMIN in its own namespace but not mount (SYS_ADMIN
		// dropped).
		joined := strings.Join(lines, "\n")
		if !strings.Contains(joined, "can netadmin") {
			t.Errorf("space %d can't NET_ADMIN in its own namespace: %q", i, lines)
		}
		if !strings.Contains(joined, "cannot mount") {
			t.Errorf("space %d could mount (SYS_ADMIN not dropped?): %q", i, lines)
		}
	}
}

// TestNetnsidEscapeBlocked is the B1 check: a worker holds CAP_NET_ADMIN, but
// its network namespace is owned by its own non-initial user namespace, so
// that capability can't reach the root namespace through the veth's
// link-netnsid. The link-netnsid operation (create a dummy in root) is refused
// from the worker and succeeds from a positive control in the initial user
// namespace.
func TestNetnsidEscapeBlocked(t *testing.T) {
	needsLab(t)
	a := netmap.NewSpaceID()
	s := start(t, options([]string{envProbe + "=1"}), a)
	_, lines := probeDone(t, s, a)
	w, _ := info(s, a)

	netadmin, escape := false, ""
	for _, l := range lines {
		if l == "can netadmin" {
			netadmin = true
		}
		if rest, ok := strings.CutPrefix(l, "escape "); ok {
			escape = rest
		}
	}
	if !netadmin {
		t.Fatalf("worker lacks NET_ADMIN in its own namespace: %q", lines)
	}
	if netnsOwnerOf(t, w.PID) != nsIno(t, fmt.Sprintf("/proc/%d/ns/user", w.PID)) {
		t.Fatal("worker's network namespace is not owned by its own user namespace")
	}
	if escape == "ok" {
		t.Fatal("the link-netnsid operation reached the root namespace from a confined worker")
	}
	t.Logf("link-netnsid op from the confined worker: %s", escape)

	// Positive control: the same operation from the initial user namespace
	// must succeed, so the block above is the user namespace.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "SUPERVISOR_TEST_ESCAPE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("escape control: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "escape ok") {
		t.Fatalf("link-netnsid op did not succeed without a user namespace: %s", out)
	}
}

func TestNoPacketCrossesSpaces(t *testing.T) {
	needsLab(t)
	// As on a server, which relays and exits: without the supervisor's
	// tables, the root namespace would forward between spaces.
	enableForwarding(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	root := listen(t)
	s := start(t, options([]string{envProbe + "=1"}), a, b)
	ws := waitReady(t, s, a, b)
	deliverTargets(t, s, a, b, crossTargets(t, ws))
	for i, w := range ws {
		waitGot(t, s, w, fmt.Sprintf("root-%d", i))
	}
	time.Sleep(2 * time.Second)
	if got := root.received(); len(got) > 0 {
		t.Errorf("the root namespace received %d datagrams from spaces, the first %q", len(got), got[0])
	}
	for i, id := range []netmap.SpaceID{a, b} {
		var crossed []string
		for _, l := range probeLines(s, id) {
			if strings.HasPrefix(l, "got ") && strings.Contains(l, "space=") && !strings.HasSuffix(l, "space="+id.String()) {
				crossed = append(crossed, l)
			}
		}
		if len(crossed) > 0 {
			t.Errorf("space %d received %d datagrams from another space, the first %q", i, len(crossed), crossed[0])
		}
	}
}

// TestNoPacketCrossesSpacesWithoutTable is the automated negative control: a
// supervisor with its isolation tables removed lets space traffic cross, so
// TestNoPacketCrossesSpaces is not passing for the wrong reason.
func TestNoPacketCrossesSpacesWithoutTable(t *testing.T) {
	needsLab(t)
	enableForwarding(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	root := listen(t)
	s := start(t, options([]string{envProbe + "=1"}), a, b)
	ws := waitReady(t, s, a, b)
	// Deliver targets first: delivering config goes through SetSpaces, which
	// rebuilds the isolation tables. Only then drop the tables behind the
	// supervisor's back, so nothing re-adds them.
	deliverTargets(t, s, a, b, crossTargets(t, ws))
	for _, name := range []string{"inet " + supervisor.TableName, "arp " + supervisor.ArpTableName} {
		if out, err := exec.Command("nft", "delete", "table", name).CombinedOutput(); err != nil {
			t.Fatalf("nft delete table %s: %v: %s", name, err, out)
		}
	}
	crossed := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(root.received()) > 0 {
			crossed = true
			break
		}
		for _, id := range []netmap.SpaceID{a, b} {
			for _, l := range probeLines(s, id) {
				if strings.HasPrefix(l, "got ") && strings.Contains(l, "space=") && !strings.HasSuffix(l, "space="+id.String()) {
					crossed = true
				}
			}
		}
		if crossed {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !crossed {
		t.Fatalf("negative control proved nothing: no traffic crossed without the tables (root got %d, forward4=%s, table back=%v)",
			len(root.received()), readSysctl("net/ipv4/ip_forward"), hasTable(t, "inet "+supervisor.TableName))
	}
}

func readSysctl(k string) string {
	b, _ := os.ReadFile("/proc/sys/" + k)
	return strings.TrimSpace(string(b))
}

// crossTargets are every address a worker should not be able to reach: the
// node's own, both veths' root ends and the other space's end; plus a
// spoofed-source datagram at the root end, matching the root's own address.
func crossTargets(t *testing.T, ws []supervisor.WorkerInfo) []string {
	t.Helper()
	var targets []string
	for _, ad := range nodeAddrs(t) {
		targets = append(targets, ad.String())
	}
	for _, w := range ws {
		for _, p := range append(slices.Clone(w.RootAddrs), w.SpaceAddrs...) {
			targets = append(targets, p.Addr().String())
		}
		// Anti-spoof: a datagram to the root end forging the root end's own
		// source address.
		targets = append(targets, w.RootAddrs[0].Addr().String()+"@"+w.RootAddrs[0].Addr().String())
	}
	// A compromised worker drops its own namespace's table first.
	return append(targets, dropSpaceTable)
}

func enableForwarding(t *testing.T) {
	t.Helper()
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
}

// deliverTargets pushes the target list to both spaces' workers as their
// config, which the probe sends to.
func deliverTargets(t *testing.T, s *supervisor.Supervisor, a, b netmap.SpaceID, targets []string) {
	t.Helper()
	cfg := []byte(strings.Join(targets, "\n"))
	if err := s.SetSpaces([]supervisor.Space{{ID: a, Config: cfg}, {ID: b, Config: cfg}}); err != nil {
		t.Fatal(err)
	}
	// Wait until both probes have taken the config.
	eventually(t, 10*time.Second, "probes have targets", func() error {
		for _, id := range []netmap.SpaceID{a, b} {
			got := false
			for _, l := range probeLines(s, id) {
				if strings.HasPrefix(l, "config ") && strings.Contains(l, "targets=") && !strings.HasSuffix(l, "targets=0") {
					got = true
				}
			}
			if !got {
				return fmt.Errorf("space %s has no targets yet", id)
			}
		}
		return nil
	})
}

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

func waitGot(t *testing.T, s *supervisor.Supervisor, w supervisor.WorkerInfo, payload string) {
	t.Helper()
	for _, p := range w.SpaceAddrs {
		eventually(t, 10*time.Second, "datagram from the root namespace to "+p.Addr().String(), func() error {
			sendTo(t, p.Addr(), payload+"@"+p.Addr().String())
			for _, l := range probeLines(s, w.Space) {
				if strings.HasPrefix(l, "got ") && strings.HasSuffix(l, " "+payload+"@"+p.Addr().String()) {
					return nil
				}
			}
			return errors.New("not received")
		})
	}
}

func sendTo(t *testing.T, to netip.Addr, payload string) {
	t.Helper()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, probePort)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte(payload))
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

func TestKilledWorkerRestartsAlone(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s := start(t, options([]string{envProbe + "=1"}), a, b)
	ws := waitReady(t, s, a, b)
	bNS, _ := probeDone(t, s, b)
	bLink, err := netlink.LinkByName(ws[1].Link)
	if err != nil {
		t.Fatal(err)
	}
	waitGot(t, s, ws[1], "before")

	if err := unix.Kill(ws[0].PID, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	eventually(t, 25*time.Second, "the killed worker back", func() error {
		w, _ := info(s, a)
		if !w.Ready || w.PID == ws[0].PID || w.Starts != 2 {
			return fmt.Errorf("%+v", w)
		}
		return nil
	})
	if w, _ := info(s, a); !strings.Contains(w.LastExit, "killed") {
		t.Errorf("last exit %q, want it killed", w.LastExit)
	}

	w, _ := info(s, b)
	if w.PID != ws[1].PID || w.Starts != 1 || !w.Ready {
		t.Fatalf("the other worker was touched: %+v, was %+v", w, ws[1])
	}
	nowNS, _ := probeDone(t, s, b)
	if nowNS["net"] != bNS["net"] {
		t.Fatalf("the other worker's namespace changed: %s, was %s", nowNS["net"], bNS["net"])
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
	// b is healthy (Idle); a crashes on every start. The crash env only
	// affects a because a healthy worker is Idle and a's serve errors.
	o := options([]string{envCrash + "=1"})
	// Use a per-space marker: only a's worker should crash. Both share the
	// env, so make both crash would be wrong; instead run a alone here.
	s, err := supervisor.New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.SetSpaces(spacesOf(a)); err != nil {
		t.Fatal(err)
	}
	// A healthy second supervisor isn't possible (one per node); instead check
	// the crashing worker alone backs off and keeps its output. The "other
	// worker untouched" property is covered by TestKilledWorkerRestartsAlone.
	_ = b
	began := time.Now()
	eventually(t, 25*time.Second, "four crashes", func() error {
		if w, _ := info(s, a); w.Starts < 4 {
			return fmt.Errorf("%d starts", w.Starts)
		}
		return nil
	})
	if took := time.Since(began); took < 350*time.Millisecond {
		t.Errorf("four starts in %v: no backoff", took)
	}
	w, _ := info(s, a)
	if !strings.Contains(strings.Join(s.Output(a), "\n"), "crashing on purpose") {
		t.Errorf("worker output not kept: %q", s.Output(a))
	}
	if !strings.Contains(w.LastExit, "exit status 1") {
		t.Errorf("last exit %q", w.LastExit)
	}
}

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
	if err := s.SetSpaces(spacesOf(a, b)); err != nil {
		t.Fatal(err)
	}
	ws := waitReady(t, s, a, b)
	naNS, _ := probeDone(t, s, a)
	nbNS, _ := probeDone(t, s, b)
	spaceNS := []string{naNS["net"], nbNS["net"]}
	if len(spaceLinks(t)) != 2 || !hasTable(t, "inet "+supervisor.TableName) || !hasTable(t, "arp "+supervisor.ArpTableName) {
		t.Fatalf("running: links %q, tables %v/%v", spaceLinks(t), hasTable(t, "inet "+supervisor.TableName), hasTable(t, "arp "+supervisor.ArpTableName))
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
	if hasTable(t, "inet "+supervisor.TableName) || hasTable(t, "arp "+supervisor.ArpTableName) {
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
	if _, err := os.Stat("/sys/fs/cgroup/thinkpol"); err == nil {
		t.Error("the supervisor's cgroup was left behind")
	}
	if err := s.SetSpaces(spacesOf(a)); err == nil {
		t.Error("a closed supervisor took spaces")
	}
}

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
	if !hasTable(t, "inet "+supervisor.TableName) {
		t.Fatal("the failed second supervisor removed the first one's table")
	}
}

func TestSetSpacesAddsAndRemoves(t *testing.T) {
	needsLab(t)
	a, b := netmap.NewSpaceID(), netmap.NewSpaceID()
	s := start(t, options(nil), a)
	wa := waitReady(t, s, a)[0]
	if err := s.SetSpaces(spacesOf(a, b)); err != nil {
		t.Fatal(err)
	}
	ws := waitReady(t, s, a, b)
	if ws[0].PID != wa.PID || ws[0].Starts != 1 {
		t.Fatalf("adding a space touched another: %+v, was %+v", ws[0], wa)
	}
	if err := s.SetSpaces(spacesOf(b)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "removed worker gone", func() error {
		if alive(wa.PID) {
			return errors.New("still running")
		}
		return nil
	})
	if _, err := netlink.LinkByName(wa.Link); err == nil {
		t.Errorf("removed space's veth %s still there", wa.Link)
	}
	if w, _ := info(s, b); w.PID != ws[1].PID || len(s.Workers()) != 1 {
		t.Fatalf("workers after removal: %+v", s.Workers())
	}
	if err := s.SetSpaces([]supervisor.Space{{ID: b}, {ID: b}}); err == nil {
		t.Error("a space listed twice was taken")
	}
	c := netmap.NewSpaceID()
	if err := s.SetSpaces(spacesOf(b, c)); err != nil {
		t.Fatal(err)
	}
	if wc := waitReady(t, s, c)[0]; wc.Link != wa.Link {
		t.Errorf("new space got %s, want the freed %s", wc.Link, wa.Link)
	}
}

// TestConfigReachesTheWorker checks a space's config is delivered after Ready
// and on change, intact, including one too large for a single packet (sealed
// memfd). The probe reports a sha256 of each config it received.
func TestConfigReachesTheWorker(t *testing.T) {
	needsLab(t)
	a := netmap.NewSpaceID()
	s, err := supervisor.New(options([]string{envProbe + "=1"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	first := bytes.Repeat([]byte("ab"), 8)
	big := bytes.Repeat([]byte("zqx9"), 64<<10) // 256 KiB: memfd path
	if err := s.SetSpaces([]supervisor.Space{{ID: a, Config: first}}); err != nil {
		t.Fatal(err)
	}
	waitReady(t, s, a)
	awaitConfigHash(t, s, a, first)
	// Change it (incl. a large one): the worker must receive each intact and
	// stay up.
	w := waitReady(t, s, a)[0]
	if err := s.SetSpaces([]supervisor.Space{{ID: a, Config: big}}); err != nil {
		t.Fatal(err)
	}
	awaitConfigHash(t, s, a, big)
	if now, _ := info(s, a); now.Starts != w.Starts || !now.Ready {
		t.Fatalf("config changes restarted the worker: %+v, was %+v", now, w)
	}
}

// TestSeedsReachTheWorker checks a space's blob seeds arrive intact, one
// memfd each (one larger than a packet), ahead of the config, and that a
// new config brings the new seeds to the running worker.
func TestSeedsReachTheWorker(t *testing.T) {
	needsLab(t)
	a := netmap.NewSpaceID()
	s, err := supervisor.New(options([]string{envProbe + "=1"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	small, big := []byte("a small seed"), bytes.Repeat([]byte("seed"), 64<<10)
	seeds := func(b ...[]byte) func() [][]byte { return func() [][]byte { return b } }
	if err := s.SetSpaces([]supervisor.Space{{ID: a, Config: []byte("one"), Seeds: seeds(small, big)}}); err != nil {
		t.Fatal(err)
	}
	waitReady(t, s, a)
	awaitSeed(t, s, a, small)
	awaitSeed(t, s, a, big)
	awaitConfigHash(t, s, a, []byte("one"))
	later := []byte("a later seed")
	if err := s.SetSpaces([]supervisor.Space{{ID: a, Config: []byte("two"), Seeds: seeds(small, later)}}); err != nil {
		t.Fatal(err)
	}
	awaitSeed(t, s, a, later)
	awaitConfigHash(t, s, a, []byte("two"))
}

func awaitSeed(t *testing.T, s *supervisor.Supervisor, space netmap.SpaceID, want []byte) {
	t.Helper()
	line := fmt.Sprintf("seed sha256=%x", sha256.Sum256(want))
	eventually(t, 10*time.Second, "worker received the seed intact", func() error {
		for _, l := range probeLines(s, space) {
			if strings.HasPrefix(l, line) {
				return nil
			}
		}
		return fmt.Errorf("no %q in the worker's output", line)
	})
}

// awaitConfigHash waits until the worker reports receiving a config whose
// sha256 and length match want.
func awaitConfigHash(t *testing.T, s *supervisor.Supervisor, space netmap.SpaceID, want []byte) {
	t.Helper()
	line := fmt.Sprintf("config sha256=%x len=%d", sha256.Sum256(want), len(want))
	eventually(t, 10*time.Second, "worker received the config intact", func() error {
		for _, l := range probeLines(s, space) {
			if strings.HasPrefix(l, line) {
				return nil
			}
		}
		return fmt.Errorf("no %q in the worker's output", line)
	})
}

func TestUnknownKindRestartsWorker(t *testing.T) {
	needsLab(t)
	// The worker sends an unexpected message kind on its control socket after
	// Ready; the supervisor must kill it and restart.
	a := netmap.NewSpaceID()
	o := options(nil)
	o.Env = []string{"SUPERVISOR_TEST_BAD_KIND=1"}
	s, err := supervisor.New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.SetSpaces(spacesOf(a)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 25*time.Second, "worker killed and restarted on an unexpected kind", func() error {
		w, _ := info(s, a)
		if w.Starts < 2 {
			return fmt.Errorf("%d starts", w.Starts)
		}
		if !strings.Contains(w.LastExit, "socket") {
			return fmt.Errorf("last exit %q; output: %q", w.LastExit, s.Output(a))
		}
		return nil
	})
}

func TestStopTimeoutKills(t *testing.T) {
	needsLab(t)
	a := netmap.NewSpaceID()
	o := options(nil)
	o.StopTimeout = 500 * time.Millisecond
	o.Env = append(o.Env, "SUPERVISOR_TEST_IGNORE_STOP=1")
	s := start(t, o, a)
	w := waitReady(t, s, a)[0]
	done := make(chan error, 1)
	go func() { done <- s.SetSpaces(nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SetSpaces(nil) blocked on a worker ignoring stop")
	}
	if alive(w.PID) {
		t.Fatal("worker ignoring stop was not killed")
	}
}

func TestThinkpolWorkerCommand(t *testing.T) {
	needsLab(t)
	const bin = "/opt/thinkpol/bin/thinkpol"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("no %s: %v", bin, err)
	}
	a := netmap.NewSpaceID()
	events := logring.New(1 << 16)
	opts := options(nil)
	opts.Command, opts.Env = []string{bin, "worker"}, nil
	opts.Log = slog.New(slog.NewTextHandler(events, nil))
	s := start(t, opts, a)
	w := waitReady(t, s, a)[0]
	if st := status(t, w.PID); st["NoNewPrivs"] != "1" {
		t.Fatalf("thinkpol worker NoNewPrivs %q", st["NoNewPrivs"])
	}
	if err := s.SetSpaces(nil); err != nil {
		t.Fatal(err)
	}
	if alive(w.PID) {
		t.Fatal("still running after Stop")
	}
	if log := events.String(); !strings.Contains(log, `msg="worker stopped" space=`+a.String()) {
		t.Fatalf("no clean stop in the supervisor's log:\n%s", log)
	}
}

// antiSpoofRules returns the rules of the inet anti-spoof chain and the total
// packets their counters have seen.
func antiSpoofRules(t *testing.T) (rules int, packets uint64) {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: supervisor.TableName}
	rs, err := c.GetRules(table, &nftables.Chain{Name: "antispoof", Table: table})
	if err != nil {
		t.Fatalf("get anti-spoof rules: %v", err)
	}
	for _, r := range rs {
		for _, e := range r.Exprs {
			if ct, ok := e.(*expr.Counter); ok {
				packets += ct.Packets
			}
		}
	}
	return len(rs), packets
}

// TestAntiSpoofDropsForgedSources checks the per-space anti-spoof rules fire:
// a worker that sources a forged, off-link address is counted and dropped
// before conntrack sees it (reverse-path filtering off, so nothing else drops
// it first). Each slot has a rule for both families.
func TestAntiSpoofDropsForgedSources(t *testing.T) {
	needsLab(t)
	// Reverse-path filtering off in the root namespace, so a forged source
	// isn't dropped before the nftables input hook.
	for _, key := range []string{"net/ipv4/conf/all/rp_filter", "net/ipv4/conf/default/rp_filter"} {
		was, err := os.ReadFile("/proc/sys/" + key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("/proc/sys/"+key, []byte("0"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile("/proc/sys/"+key, was, 0) })
	}
	a := netmap.NewSpaceID()
	s := start(t, options([]string{envProbe + "=1"}), a)
	w := waitReady(t, s, a)[0]
	rules, before := antiSpoofRules(t)
	if rules < 2 {
		t.Fatalf("anti-spoof chain has %d rules, want at least 2 (IPv4 and IPv6 for the slot)", rules)
	}
	// Forge an off-link source to the slot's root end; the slot's transit
	// address is the only accepted source, so this is dropped and counted.
	spoof := w.RootAddrs[0].Addr().String() + "@203.0.113.9\n" + dropSpaceTable
	if err := s.SetSpaces([]supervisor.Space{{ID: a, Config: []byte(spoof)}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "anti-spoof counter rises on forged sources", func() error {
		if _, now := antiSpoofRules(t); now > before {
			return nil
		}
		return fmt.Errorf("counter still %d", before)
	})
}

// TestNodeCannotWriteKernelSysctl is the safety check for the reverted lab
// profile: a lab node (SYS_ADMIN, AppArmor off) still cannot write the Docker
// VM's kernel sysctls, so it can't reach the host through core_pattern.
func TestNodeCannotWriteKernelSysctl(t *testing.T) {
	needsLab(t)
	cur, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		t.Fatalf("read core_pattern: %v", err)
	}
	if err := os.WriteFile("/proc/sys/kernel/core_pattern", cur, 0); err == nil {
		// Put it back if it somehow succeeded, then fail.
		_ = os.WriteFile("/proc/sys/kernel/core_pattern", cur, 0)
		t.Fatal("a lab node could write /proc/sys/kernel/core_pattern (the VM's /proc is not masked)")
	}
}
