//go:build linux && !android

package supervisor_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const (
	envShared           = "SUPERVISOR_TEST_SHARED"            // set: the worker serves udp behind the shared listener
	envSharedSupervisor = "SUPERVISOR_TEST_SHARED_SUPERVISOR" // a setup file: this process is a supervisor of shared spaces
	sharedPort          = 7443
)

// sharedConfig is a test worker's config: its own map's inbound udp links.
type sharedConfig struct {
	Inbound []transport.PeerLink `json:"inbound"`
}

// sharedServe is a worker's data plane reduced to its listeners: udp
// behind the supervisor's shared listener, for the links its own map
// lists. It reports every link it accepts and every packet ("probe ..."
// lines), echoes packets starting with "echo", only counts those starting
// with "bulk", and reports its listener's counters.
func sharedServe(ctx context.Context, s worker.Session) error {
	say := func(format string, args ...any) { fmt.Fprintf(os.Stderr, "probe "+format+"\n", args...) }
	peers := transport.NewPeerTable()
	reg, err := transport.NewRegistry(udp.New(udp.Options{}))
	if err != nil {
		return err
	}
	var bulk atomic.Uint64
	var listeners []*udp.Listener
	serving := map[uint32]bool{}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case b := <-s.Config:
			var c sharedConfig
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			for _, pl := range c.Inbound {
				if pl.Peer.Space != transport.SpaceID(s.Space) {
					return fmt.Errorf("an inbound link of space %s", pl.Peer.Space)
				}
			}
			peers.Set(c.Inbound)
			say("config links=%d", len(c.Inbound))
		case ls := <-s.Listeners:
			for _, l := range ls {
				if serving[l.ID] || l.Stream || l.Transport != udp.Name {
					continue
				}
				serving[l.ID] = true
				tl, err := l.Listen(reg, transport.Accept{Peers: peers})
				if err != nil {
					return err
				}
				ul := tl.(*udp.Listener)
				listeners = append(listeners, ul)
				go acceptLinks(ctx, ul, say, &bulk)
			}
			say("listeners %d", len(serving))
		case c := <-s.SharedCounters:
			say("shared forwarded=%d replies=%d replayed=%d", c.Forwarded, c.Replies, c.Replayed)
		case <-tick.C:
			var c udp.Counters
			for _, l := range listeners {
				lc := l.Counters()
				c.Delivered += lc.Delivered
				c.Unauthenticated += lc.Unauthenticated
				c.Replayed += lc.Replayed
			}
			say("counters delivered=%d unauthenticated=%d replayed=%d", c.Delivered, c.Unauthenticated, c.Replayed)
			say("bytes %d at %d", bulk.Load(), time.Now().UnixNano())
			say("drops %+v", s.SharedDrops())
		}
	}
}

func acceptLinks(ctx context.Context, l *udp.Listener, say func(string, ...any), bulk *atomic.Uint64) {
	for {
		link, id, err := l.Accept(ctx)
		if err != nil {
			return
		}
		say("accepted %s", id)
		go func() {
			buf := make([]byte, transport.MaxPacketSize)
			for {
				n, err := link.ReadPacket(buf)
				if err != nil {
					return
				}
				p := buf[:n]
				switch {
				case strings.HasPrefix(string(p), "bulk"):
					bulk.Add(uint64(n))
				case strings.HasPrefix(string(p), "echo"):
					_ = link.WritePacket(p)
				default:
					say("packet %s %s", id, p)
					_ = link.WritePacket(append([]byte("reply "), p...))
				}
			}
		}()
	}
}

// sharedSpace is one space of a shared-listener test: its id, the dialers
// its hand-made map accepts, and the supervisor's view of it.
type sharedSpace struct {
	ID      netmap.SpaceID
	Dialers []dialer
	Space   supervisor.Space
}

type dialer struct {
	Node   netmap.NodeID
	Secret []byte
}

func newDialer() dialer {
	return dialer{Node: netmap.NodeID(randomBytes(8)), Secret: randomBytes(32)}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// handMadeSpace is a space whose map section (written by hand, a server
// with ingress on) lets dialers in over udp. Its inbound table and its worker's config both come
// from that section, through the engine's conversion, as `thinkpol up`
// will do it.
func handMadeSpace(t testing.TB, dialers ...dialer) sharedSpace {
	t.Helper()
	sp := sharedSpace{ID: netmap.NewSpaceID(), Dialers: dialers}
	section := netmap.Section{Node: netmap.NodeSettings{ID: netmap.NodeID(randomBytes(8)), Kind: netmap.NodeServer, AllowIngress: true}}
	for _, d := range dialers {
		section.Inbound = append(section.Inbound, netmap.InboundLink{Peer: d.Node, PeerKind: netmap.NodeDevice, Transport: udp.Name, Credential: d.Secret})
	}
	reg, err := transport.NewRegistry(udp.New(udp.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	in := dataplane.AcceptedInbound(section, reg, transport.SpaceID(sp.ID), 0)
	if len(in.Skipped) > 0 {
		t.Fatalf("skipped %v", in.Skipped)
	}
	config, err := json.Marshal(sharedConfig{Inbound: in.Links[udp.Name]})
	if err != nil {
		t.Fatal(err)
	}
	sp.Space = supervisor.Space{ID: sp.ID, Config: config, Inbound: in.Links}
	return sp
}

func sharedOptions() supervisor.Options {
	o := options([]string{envShared + "=1"})
	reg, _ := transport.NewRegistry(udp.New(udp.Options{}))
	o.Transports = reg
	o.CountersInterval = 200 * time.Millisecond
	return o
}

func publicAddress() string { return fmt.Sprintf("127.0.0.1:%d", sharedPort) }

func dialSpace(t *testing.T, d dialer) transport.Link {
	t.Helper()
	l, err := udp.New(udp.Options{}).Dial(context.Background(), publicAddress(), transport.DialConfig{Credential: d.Secret})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func hasLine(s *supervisor.Supervisor, space netmap.SpaceID, prefix string) bool {
	for _, l := range probeLines(s, space) {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func lastLine(s *supervisor.Supervisor, space netmap.SpaceID, prefix string) string {
	var last string
	for _, l := range probeLines(s, space) {
		if strings.HasPrefix(l, prefix) {
			last = l
		}
	}
	return last
}

// TP-010's acceptance: two spaces on one server, from hand-made maps,
// behind one public udp socket. Each worker gets only its own links, the
// replies leave through the public socket, and nothing that fails
// authentication reaches either worker.
func TestTwoSpacesShareAListener(t *testing.T) {
	needsLab(t)
	a1, a2, b1 := newDialer(), newDialer(), newDialer()
	spA, spB := handMadeSpace(t, a1, a2), handMadeSpace(t, b1)
	s, err := supervisor.New(sharedOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := s.SetSpaces([]supervisor.Space{spA.Space, spB.Space}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetListeners([]supervisor.Listener{{Transport: udp.Name, Address: fmt.Sprintf("0.0.0.0:%d", sharedPort)}}); err != nil {
		t.Fatal(err)
	}
	waitReady(t, s, spA.ID, spB.ID)
	for _, sp := range []sharedSpace{spA, spB} {
		eventually(t, 10*time.Second, "the worker serving the listener", func() error {
			if !hasLine(s, sp.ID, "listeners 1") || !hasLine(s, sp.ID, "config links=") {
				return fmt.Errorf("output %q", s.Output(sp.ID))
			}
			return nil
		})
	}

	// Strangers first: a secret no map lists, a dialer of A's with one
	// byte of its secret changed, and junk.
	stranger := newDialer()
	forged := a1
	forged.Secret = append([]byte(nil), a1.Secret...)
	forged.Secret[0] ^= 1
	for _, d := range []dialer{stranger, forged} {
		if err := dialSpace(t, d).WritePacket([]byte("let me in")); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := net.Dial("udp", publicAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	for _, n := range []int{1, udp.Overhead, 200, 1400} {
		_, _ = raw.Write(randomBytes(n))
	}
	eventually(t, 5*time.Second, "the strangers turned away", func() error {
		if ls := s.Listeners(); len(ls) != 1 || ls[0].Unauthenticated != 6 {
			return fmt.Errorf("listeners %+v", ls)
		}
		return nil
	})

	links := map[netmap.NodeID]transport.Link{}
	for _, sp := range []sharedSpace{spA, spB} {
		for _, d := range sp.Dialers {
			links[d.Node] = dialSpace(t, d)
			if err := links[d.Node].WritePacket([]byte("hello from " + d.Node.String())); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, sp := range []sharedSpace{spA, spB} {
		for _, d := range sp.Dialers {
			id := transport.Identity{Space: transport.SpaceID(sp.ID), Node: transport.NodeID(d.Node)}
			eventually(t, 5*time.Second, "the link at its worker", func() error {
				if !hasLine(s, sp.ID, "accepted "+id.String()) || !hasLine(s, sp.ID, "packet "+id.String()+" hello from "+d.Node.String()) {
					return fmt.Errorf("output %q", probeLines(s, sp.ID))
				}
				return nil
			})
			buf := make([]byte, 256)
			got := make(chan string, 1)
			go func() {
				n, _ := links[d.Node].ReadPacket(buf)
				got <- string(buf[:n])
			}()
			select {
			case r := <-got:
				if r != "reply hello from "+d.Node.String() {
					t.Fatalf("dialer %s got %q", d.Node, r)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no reply for dialer %s", d.Node)
			}
		}
	}
	// Each worker accepted exactly its own links and nothing else ever
	// reached it: its udp listener saw no datagram it couldn't
	// authenticate.
	for _, sp := range []sharedSpace{spA, spB} {
		var accepted []string
		for _, l := range probeLines(s, sp.ID) {
			if rest, ok := strings.CutPrefix(l, "accepted "); ok {
				accepted = append(accepted, rest)
			}
		}
		if len(accepted) != len(sp.Dialers) {
			t.Errorf("space %s accepted %q, want its %d dialers", sp.ID, accepted, len(sp.Dialers))
		}
		for _, id := range accepted {
			if !strings.HasPrefix(id, sp.ID.String()+"/") {
				t.Errorf("space %s accepted a link of %s", sp.ID, id)
			}
		}
		eventually(t, 5*time.Second, "the worker's counters", func() error {
			want := fmt.Sprintf("counters delivered=%d unauthenticated=0 replayed=0", len(sp.Dialers))
			if got := lastLine(s, sp.ID, "counters "); got != want {
				return fmt.Errorf("%q, want %q", got, want)
			}
			return nil
		})
		// The worker gets its space's counters for its telemetry.
		eventually(t, 5*time.Second, "the counters at the worker", func() error {
			want := fmt.Sprintf("shared forwarded=%d replies=%d replayed=0", len(sp.Dialers), len(sp.Dialers))
			if got := lastLine(s, sp.ID, "shared "); got != want {
				return fmt.Errorf("%q, want %q", got, want)
			}
			return nil
		})
		w, _ := info(s, sp.ID)
		if w.Shared.Forwarded != uint64(len(sp.Dialers)) || w.Shared.Replies != uint64(len(sp.Dialers)) || w.Shared.RepliesNotAllowed != 0 {
			t.Errorf("space %s: %+v", sp.ID, w.Shared)
		}
	}
}

// The setup a shared supervisor process reads.
type sharedSetup struct {
	Spaces []supervisor.Space `json:"spaces"`
}

// runSharedSupervisor is a supervisor in a process of its own (pinned to
// one CPU by the test), serving the spaces of a setup file on the shared
// listener. It prints "ready" once its workers serve, then its workers'
// "bytes" lines as "<space> <line>", until SIGTERM.
func runSharedSupervisor() int {
	b, err := os.ReadFile(os.Getenv(envSharedSupervisor))
	var setup sharedSetup
	if err == nil {
		err = json.Unmarshal(b, &setup)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	s, err := supervisor.New(sharedOptions())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = s.Close() }()
	err = s.SetSpaces(setup.Spaces)
	if err == nil {
		err = s.SetListeners([]supervisor.Listener{{Transport: udp.Name, Address: fmt.Sprintf("0.0.0.0:%d", sharedPort)}})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ready := false
	for !ready {
		select {
		case <-ctx.Done():
			return 1
		case <-time.After(50 * time.Millisecond):
		}
		ready = true
		for _, sp := range setup.Spaces {
			if !hasLine(s, sp.ID, "listeners 1") {
				ready = false
			}
		}
	}
	var pids []string
	for _, w := range s.Workers() {
		pids = append(pids, strconv.Itoa(w.PID))
	}
	fmt.Println("ready", strings.Join(pids, " "))
	for {
		select {
		case <-ctx.Done():
			for _, w := range s.Workers() {
				fmt.Printf("%s shared %+v\n", w.Space, w.Shared)
			}
			return 0
		case <-time.After(100 * time.Millisecond):
		}
		for _, sp := range setup.Spaces {
			if l := lastLine(s, sp.ID, "bytes "); l != "" {
				fmt.Println(sp.ID.String(), l)
			}
		}
		for _, w := range s.Workers() {
			if b, err := json.Marshal(w.Shared); err == nil {
				fmt.Printf("%s counters %s\n", w.Space, b)
			}
		}
		for _, l := range s.Listeners() {
			fmt.Printf("listener routed=%d unauthenticated=%d\n", l.Routed, l.Unauthenticated)
		}
	}
}

// pinTo moves every thread of this process to cpus (taskset's list
// syntax), so the load it generates stays off the supervisor's CPU.
func pinTo(t *testing.T, cpus string) {
	t.Helper()
	if out, err := exec.Command("taskset", "-a", "-cp", cpus, strconv.Itoa(os.Getpid())).CombinedOutput(); err != nil {
		t.Fatalf("taskset: %v: %s", err, out)
	}
}

// TestSharedListenerThroughput measures what the shared listener carries
// with the supervisor and both workers pinned to one CPU (PRD
// Performance: ≥ 50 Mbit/s on a 1-vCPU node): one-way into a worker, then
// an echo through it (both directions at once), with 1400-byte packets
// from dialers on other CPUs. Two spaces are served, the second idle. It
// measures only under make lab-perf (THINKPOL_LAB_PERF=1); make lab-test
// checks the handoff alone.
func TestSharedListenerThroughput(t *testing.T) {
	needsLab(t)
	if n, _ := strconv.Atoi(strings.TrimSpace(mustOutput(t, "nproc"))); n < 2 {
		t.Skip("needs a second CPU for the load")
	}
	d := newDialer()
	busy, idle := handMadeSpace(t, d), handMadeSpace(t, newDialer())
	setup, err := json.Marshal(sharedSetup{Spaces: []supervisor.Space{busy.Space, idle.Space}})
	if err != nil {
		t.Fatal(err)
	}
	file := t.TempDir() + "/setup.json"
	if err := os.WriteFile(file, setup, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("taskset", "-c", "0", os.Args[0])
	cmd.Env = append(os.Environ(), envSharedSupervisor+"="+file)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	cpus := mustCPUs(t)
	pinTo(t, "1-"+strconv.Itoa(cpus-1))
	t.Cleanup(func() { pinTo(t, "0-"+strconv.Itoa(cpus-1)) })

	var mu sync.Mutex
	var lastBytes uint64
	var lastAt int64
	var counters supervisor.SharedCounters
	var routed uint64
	ready := make(chan []string, 1)
	finished := make(chan []string, 1)
	go func() {
		var tail []string
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "ready"):
				ready <- strings.Fields(line)[1:]
			case strings.HasPrefix(line, busy.ID.String()+" bytes "):
				var n uint64
				var at int64
				if _, err := fmt.Sscanf(strings.TrimPrefix(line, busy.ID.String()+" "), "bytes %d at %d", &n, &at); err == nil {
					mu.Lock()
					lastBytes, lastAt = n, at
					mu.Unlock()
				}
			case strings.HasPrefix(line, busy.ID.String()+" counters "):
				var c supervisor.SharedCounters
				if json.Unmarshal([]byte(strings.TrimPrefix(line, busy.ID.String()+" counters ")), &c) == nil {
					mu.Lock()
					counters = c
					mu.Unlock()
				}
			case strings.HasPrefix(line, "listener routed="):
				var r, u uint64
				if _, err := fmt.Sscanf(line, "listener routed=%d unauthenticated=%d", &r, &u); err == nil {
					mu.Lock()
					routed = r
					mu.Unlock()
				}
			case strings.Contains(line, " shared "):
				tail = append(tail, line)
			}
		}
		finished <- tail
	}()
	var workers []string
	select {
	case workers = <-ready:
	case <-time.After(40 * time.Second):
		t.Fatal("the supervisor's workers never served")
	}
	// The supervisor and its workers, every thread, may run on CPU 0 only.
	for _, pid := range append(workers, strconv.Itoa(cmd.Process.Pid)) {
		tasks, err := os.ReadDir("/proc/" + pid + "/task")
		if err != nil {
			t.Fatal(err)
		}
		for _, task := range tasks {
			status, err := os.ReadFile("/proc/" + pid + "/task/" + task.Name() + "/status")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(status), "Cpus_allowed_list:\t0\n") {
				t.Fatalf("process %s thread %s isn't pinned to CPU 0", pid, task.Name())
			}
		}
	}
	t.Logf("supervisor %d and workers %v pinned to CPU 0", cmd.Process.Pid, workers)
	sample := func() (uint64, int64) {
		mu.Lock()
		defer mu.Unlock()
		return lastBytes, lastAt
	}

	link := dialSpace(t, d)
	const size = 1400
	packet := func(prefix string) []byte {
		p := make([]byte, size)
		copy(p, prefix)
		return p
	}
	snapshot := func() (supervisor.SharedCounters, uint64, uint64) {
		time.Sleep(300 * time.Millisecond) // the next reports
		mu.Lock()
		defer mu.Unlock()
		return counters, routed, lastBytes
	}

	// Paced: 100 Mbit/s in 1 ms bursts for 4 s, a realistic load at twice
	// the target, which should lose (almost) nothing.
	paced := func() (loss, workerLoss float64) {
		const rate = 100e6 / 8 / size // packets per second
		c0, r0, b0 := snapshot()
		var sent uint64
		tick := time.NewTicker(time.Millisecond)
		for begin := time.Now(); time.Since(begin) < 4*time.Second; {
			<-tick.C
			for due := uint64(time.Since(begin).Seconds() * rate); sent < due; sent++ {
				if err := link.WritePacket(packet("bulk")); err != nil {
					t.Fatal(err)
				}
			}
		}
		tick.Stop()
		c1, r1, b1 := snapshot()
		forwarded := c1.Forwarded - c0.Forwarded
		loss = 1 - float64(forwarded)/float64(sent)
		// What the worker's link delivered: past its queues, the
		// transport's second open and replay filter.
		delivered := (b1 - b0) / size
		workerLoss = 1 - float64(delivered)/float64(sent)
		t.Logf("paced 100 Mbit/s: %d sent, %d routed, %d forwarded to the worker (%d worker full), %d delivered by its link: loss %.3f%% at the handoff, %.3f%% at the worker",
			sent, r1-r0, forwarded, c1.WorkerFull-c0.WorkerFull, delivered, 100*loss, 100*workerLoss)
		return loss, workerLoss
	}

	stop := make(chan struct{})
	var sent atomic.Uint64
	var wg sync.WaitGroup
	send := func(p []byte) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if link.WritePacket(p) == nil {
				sent.Add(1)
			}
		}
	}
	// One-way: the worker counts what it gets.
	oneWay := func() float64 {
		stop = make(chan struct{})
		wg.Add(1)
		go send(packet("bulk"))
		time.Sleep(time.Second) // warm up
		b0, t0 := sample()
		time.Sleep(4 * time.Second)
		b1, t1 := sample()
		close(stop)
		wg.Wait()
		if t1 <= t0 {
			t.Fatal("no byte counts from the worker")
		}
		mbit := float64(b1-b0) * 8 / (float64(t1-t0) / 1e9) / 1e6
		t.Logf("one way: %.1f Mbit/s delivered to the worker (%d packets offered)", mbit, sent.Load())
		return mbit
	}
	// Echo: the worker sends back everything it gets; count what returns.
	var echoed atomic.Uint64
	var reading sync.Once
	echo := func() float64 {
		reading.Do(func() {
			go func() {
				buf := make([]byte, transport.MaxPacketSize)
				for {
					n, err := link.ReadPacket(buf)
					if err != nil {
						return
					}
					echoed.Add(uint64(n))
				}
			}()
		})
		stop = make(chan struct{})
		wg.Add(1)
		go send(packet("echo"))
		time.Sleep(time.Second)
		e0, s0 := echoed.Load(), time.Now()
		time.Sleep(4 * time.Second)
		e1, s1 := echoed.Load(), time.Now()
		close(stop)
		wg.Wait()
		mbit := float64(e1-e0) * 8 / s1.Sub(s0).Seconds() / 1e6
		t.Logf("echo: %.1f Mbit/s each way through the shared listener", mbit)
		return mbit
	}
	measure := func() throughput {
		var m throughput
		m.loss, m.workerLoss = paced()
		m.oneWay = oneWay()
		m.echo = echo()
		time.Sleep(time.Second) // the last echoes drain
		return m
	}

	// The targets are a performance gate, checked only by make lab-perf
	// (THINKPOL_LAB_PERF=1), which runs alone on the host and measures up
	// to three times. make lab-test shares the machine with other labs, so
	// there the test checks only what load can't change: a working handoff
	// that loses nothing it has room for. Echoes go with at most window
	// packets in flight, which none of the path's queues (the public
	// socket, the data socket, the worker's queue) can overflow, so every
	// one must come back, however slowly.
	perf := os.Getenv("THINKPOL_LAB_PERF") != ""
	var m throughput
	if perf {
		m = measure()
		if !m.meetsTargets() {
			t.Logf("first measurement %s misses the targets: measuring twice more", m)
			m = medianThroughput(m, measure(), measure())
			t.Logf("median of three: %s", m)
		}
	} else {
		const packets, window = 2000, 32
		echoes := make(chan struct{}, window)
		go func() {
			buf := make([]byte, transport.MaxPacketSize)
			for {
				if _, err := link.ReadPacket(buf); err != nil {
					return
				}
				echoes <- struct{}{}
			}
		}()
		sent, back := 0, 0
	handoff:
		for back < packets {
			for ; sent < packets && sent-back < window; sent++ {
				if err := link.WritePacket(packet("echo")); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-echoes:
				back++
			case <-time.After(30 * time.Second):
				break handoff
			}
		}
		if back != packets {
			t.Errorf("the shared listener doesn't hand off: %d of %d echoes came back, %d in flight at most", back, packets, window)
		} else {
			t.Logf("%d echoes through the handoff, %d in flight at most (targets checked by make lab-perf)", packets, window)
		}
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case tail := <-finished:
		for _, l := range tail {
			t.Log(l)
		}
	case <-time.After(15 * time.Second):
	}
	if perf {
		if m.loss >= 0.005 || m.workerLoss >= 0.005 {
			t.Errorf("lost %.3f%% at the handoff and %.3f%% at the worker at 100 Mbit/s, want under 0.5%%", 100*m.loss, 100*m.workerLoss)
		}
		if m.oneWay < 50 || m.echo < 50 {
			t.Errorf("below the 50 Mbit/s target on one CPU: one way %.1f, echo %.1f", m.oneWay, m.echo)
		}
	}
}

func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(out)
}

func mustCPUs(t *testing.T) int {
	n, err := strconv.Atoi(strings.TrimSpace(mustOutput(t, "nproc")))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// throughput is one measurement of TestSharedListenerThroughput: paced
// loss at the handoff and at the worker, one-way and echo Mbit/s.
type throughput struct{ loss, workerLoss, oneWay, echo float64 }

// meetsTargets: under 0.5% loss at 100 Mbit/s, at least 50 Mbit/s one way
// and each way through the echo (PRD Performance, on one CPU).
func (m throughput) meetsTargets() bool {
	return m.loss < 0.005 && m.workerLoss < 0.005 && m.oneWay >= 50 && m.echo >= 50
}

func (m throughput) String() string {
	return fmt.Sprintf("loss %.3f%% at the handoff, %.3f%% at the worker; one way %.1f Mbit/s, echo %.1f Mbit/s", 100*m.loss, 100*m.workerLoss, m.oneWay, m.echo)
}

// medianThroughput takes each figure's median on its own.
func medianThroughput(a, b, c throughput) throughput {
	med := func(x, y, z float64) float64 {
		v := []float64{x, y, z}
		slices.Sort(v)
		return v[1]
	}
	return throughput{
		loss:       med(a.loss, b.loss, c.loss),
		workerLoss: med(a.workerLoss, b.workerLoss, c.workerLoss),
		oneWay:     med(a.oneWay, b.oneWay, c.oneWay),
		echo:       med(a.echo, b.echo, c.echo),
	}
}
