package path_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
)

// Wall-clock timings: a silent link is down after 150 ms.
var fastOptions = path.Options{
	ProbeInterval: 30 * time.Millisecond,
	DeadAfter:     150 * time.Millisecond,
	FollowFor:     150 * time.Millisecond,
	RedialMin:     10 * time.Millisecond,
	RedialMax:     100 * time.Millisecond,
	Selector:      path.Failover{HoldDown: 500 * time.Millisecond},
}

// Timings for a fake clock, which tests step by fakeStep, giving the nodes
// fakeSlack of wall time per step. A link probed every ProbeInterval has
// (DeadAfter - ProbeInterval) / fakeStep steps, 200 ms of wall time, for a
// reply to come back: room for a race-detector stall.
var fakeOptions = path.Options{
	ProbeInterval: time.Second,
	DeadAfter:     5 * time.Second,
	FollowFor:     5 * time.Second,
	RedialMin:     5 * time.Millisecond, // wall clock
	RedialMax:     20 * time.Millisecond,
	Selector:      path.Failover{HoldDown: 10 * time.Second},
}

const (
	fakeStep  = 100 * time.Millisecond
	fakeSlack = 5 * time.Millisecond
	fakeHold  = 10 * time.Second // fakeOptions' hold-down
)

// wait bounds every wall-clock wait for something that should happen.
const wait = 10 * time.Second

// eachSemantics runs a test over a datagram and a stream memory transport.
func eachSemantics(t *testing.T, test func(t *testing.T, f *fabric)) {
	for _, sem := range []memory.Semantics{memory.Datagram, memory.Stream} {
		t.Run(sem.String(), func(t *testing.T) {
			t.Parallel()
			test(t, newFabric(t, sem))
		})
	}
}

// eachSemanticsFake is eachSemantics with a fake clock.
func eachSemanticsFake(t *testing.T, test func(t *testing.T, f *fabric)) {
	for _, sem := range []memory.Semantics{memory.Datagram, memory.Stream} {
		t.Run(sem.String(), func(t *testing.T) {
			t.Parallel()
			test(t, newFakeFabric(t, sem))
		})
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fabric is a set of nodes on one memory network. Links can be silenced:
// their packets vanish in both directions without an error, as on a
// datagram transport whose far end died or a censor started dropping.
type fabric struct {
	t     *testing.T
	tr    *memory.Network
	opts  path.Options
	clock *fakeClock // nil on the wall clock

	mu       sync.Mutex
	silenced map[string]bool // "from>to" for what from sends, "from<to" for what it receives
	nodes    map[string]*fnode
}

type fnode struct {
	*path.Node
	name    string
	peers   *transport.PeerTable
	inbound []transport.PeerLink
	table   path.Table
}

func newFabric(t *testing.T, sem memory.Semantics) *fabric {
	return &fabric{t: t, tr: memory.NewNetwork(sem), opts: fastOptions, silenced: map[string]bool{}, nodes: map[string]*fnode{}}
}

func newFakeFabric(t *testing.T, sem memory.Semantics) *fabric {
	f := newFabric(t, sem)
	f.clock = &fakeClock{now: time.Unix(1_000_000, 0)}
	f.opts = path.WatchEvery(fakeOptions, time.Millisecond)
	f.opts.Now = f.clock.Now
	return f
}

// advance steps the fake clock by d, giving the nodes time to probe and
// answer at every step, and calls each (if any) after every step.
func (f *fabric) advance(d time.Duration, each func()) {
	for done := time.Duration(0); done < d; done += fakeStep {
		f.clock.add(fakeStep)
		time.Sleep(fakeSlack)
		if each != nil {
			each()
		}
	}
}

func id(name string) path.NodeID {
	var id path.NodeID
	copy(id[:], name)
	return id
}

func hexID(name string) string {
	i := id(name)
	return hex.EncodeToString(i[:])
}

// add starts nodes, each listening on the memory network under its name.
func (f *fabric) add(names ...string) {
	f.t.Helper()
	for _, name := range names {
		node, err := path.NewNode(id(name), f.opts)
		if err != nil {
			f.t.Fatal(err)
		}
		n := &fnode{Node: node, name: name, peers: transport.NewPeerTable()}
		l, err := f.tr.Listen(context.Background(), transport.ListenConfig{Address: name, Peers: n.peers})
		if err != nil {
			f.t.Fatal(err)
		}
		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = n.Serve(memory.Name, l)
		}()
		f.t.Cleanup(func() {
			_ = n.Close()
			_ = l.Close()
			<-served
		})
		f.mu.Lock()
		f.nodes[name] = n
		f.mu.Unlock()
	}
}

func (f *fabric) node(name string) *fnode {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[name]
	if n == nil {
		f.t.Fatalf("no node %s", name)
	}
	return n
}

// accept lets from dial to with a secret, and returns the secret.
func (f *fabric) accept(to, from string, space transport.SpaceID) []byte {
	b := f.node(to)
	secret := []byte("secret " + from + ">" + to)
	b.inbound = append(b.inbound, transport.PeerLink{Peer: transport.Identity{Space: space, Node: id(from)}, Verifier: secret})
	b.peers.Set(b.inbound)
	return secret
}

// dial makes from keep a link to to, and waits until it is up.
func (f *fabric) dial(from, to string) {
	f.t.Helper()
	secret := f.accept(to, from, transport.SpaceID{})
	a := f.node(from)
	a.table.Links = append(a.table.Links, path.Link{Node: id(to), Endpoints: []path.Endpoint{{
		Transport: memory.Name,
		Dialer:    silenceable{f: f, from: from, to: to},
		Address:   to,
		Config:    transport.DialConfig{Credential: secret},
	}}})
	a.Update(a.table)
	f.waitUp(from, to)
}

// route adds a route at a node: packets for dst go through next hops.
func (f *fabric) route(at, dst string, next ...string) {
	n := f.node(at)
	r := path.Route{Destination: id(dst)}
	for _, h := range next {
		r.NextHops = append(r.NextHops, id(h))
	}
	n.table.Routes = append(n.table.Routes, r)
	n.Update(n.table)
}

// silence makes the links from dials to go quiet both ways, or stops it.
func (f *fabric) silence(from, to string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.silenced[from+">"+to] = on
	f.silenced[from+"<"+to] = on
}

// silenceInbound loses only what to sends to from, on the links from dials.
func (f *fabric) silenceInbound(from, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.silenced[from+"<"+to] = true
}

func (f *fabric) isSilenced(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.silenced[key]
}

func (f *fabric) neighbor(at, of string) (path.NeighborStatus, bool) {
	for _, s := range f.node(at).Neighbors() {
		if s.Node == id(of) {
			return s, true
		}
	}
	return path.NeighborStatus{}, false
}

func (f *fabric) isUp(at, of string) bool {
	s, ok := f.neighbor(at, of)
	return ok && s.Up
}

// waitUp waits until at's link to of is up. On a fake clock it steps the
// clock meanwhile: a first dial can race the listener's table update and
// open a link that never hears back, which goes only when DeadAfter passes.
func (f *fabric) waitUp(at, of string) {
	f.t.Helper()
	eventually(f.t, at+" sees "+of+" up", func() bool {
		if f.clock != nil {
			f.clock.add(fakeStep)
		}
		return f.isUp(at, of)
	})
}

// rawLink dials to as from, outside any node, and returns the link once
// to answers a probe on it. Like any adjacent node it answers to's probes,
// so to keeps counting the link as up.
func (f *fabric) rawLink(from, to string) transport.Link {
	f.t.Helper()
	secret := f.accept(to, from, transport.SpaceID{})
	probe := []byte{2, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	var l transport.Link
	// The listener takes up a table change on its own time: redial until
	// a probe is answered, as the path layer does.
	eventually(f.t, to+" answers a probe", func() bool {
		try, err := f.tr.Dial(context.Background(), to, transport.DialConfig{Credential: secret})
		if err != nil {
			f.t.Fatal(err)
		}
		replies := make(chan []byte, 1)
		go func() {
			buf := make([]byte, transport.MaxPacketSize)
			for {
				n, err := try.ReadPacket(buf)
				if err != nil {
					return
				}
				switch buf[0] {
				case 2:
					_ = try.WritePacket(append([]byte{3}, buf[1:n]...))
				case 3:
					select {
					case replies <- append([]byte(nil), buf[:n]...):
					default:
					}
				}
			}
		}()
		if err := try.WritePacket(probe); err != nil {
			f.t.Fatal(err)
		}
		select {
		case got := <-replies:
			if want := append([]byte{3}, probe[1:]...); !bytes.Equal(got, want) {
				f.t.Fatalf("probe answered with %x, want %x", got, want)
			}
			l = try
			return true
		case <-time.After(50 * time.Millisecond):
			_ = try.Close()
			return false
		}
	})
	f.t.Cleanup(func() { _ = l.Close() })
	return l
}

// packet is a packet frame spoken by hand.
func packet(hops byte, dst, src string, msg []byte) []byte {
	d, s := id(dst), id(src)
	return append(append(append([]byte{1, hops}, d[:]...), s[:]...), msg...)
}

// WireGuard-shaped messages: what the path layer counts as signs of life.
// wgMsg is a WireGuard-shaped data message carrying a tag (≤ 32 bytes).
func wgMsg(tag string) []byte {
	m := make([]byte, 48)
	m[0] = 4
	copy(m[16:], tag)
	return m
}

func tagOf(m []byte) string {
	if len(m) != 48 {
		return string(m)
	}
	return string(bytes.TrimRight(m[16:], "\x00"))
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// exchange is one round of traffic that tolerates loss: A sends, B answers
// whatever reached it to the endpoint it came with, as WireGuard does, and
// A takes what came back. It returns the hops each end is on.
func exchange(a, b *rawBind, toB conn.Endpoint, msg []byte) (aHop, bHop string) {
	_ = a.Send([][]byte{msg}, toB)
	if r, ok := b.drain(); ok {
		_ = b.Send([][]byte{wgMsg("answer")}, r.ep)
	}
	a.drain()
	return a.current("B"), b.current("A")
}

// silenceable dials over the fabric's network; the links it opens go quiet
// while the fabric silences them.
type silenceable struct {
	f        *fabric
	from, to string
}

func (d silenceable) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	l, err := d.f.tr.Dial(ctx, endpoint, cfg)
	if err != nil {
		return nil, err
	}
	return &silenceableLink{
		Link: l,
		out:  func() bool { return d.f.isSilenced(d.from + ">" + d.to) },
		in:   func() bool { return d.f.isSilenced(d.from + "<" + d.to) },
	}, nil
}

type silenceableLink struct {
	transport.Link
	out, in func() bool
}

func (l *silenceableLink) WritePacket(p []byte) error {
	if l.out() {
		return transport.CheckPacketSize(p)
	}
	return l.Link.WritePacket(p)
}

func (l *silenceableLink) ReadPacket(p []byte) (int, error) {
	for {
		n, err := l.Link.ReadPacket(p)
		if err != nil || !l.in() {
			return n, err
		}
	}
}

// rawBind drives a Bind the way WireGuard does, without WireGuard.
type rawBind struct {
	*path.Bind
	got chan received
}

type received struct {
	msg []byte
	ep  conn.Endpoint
}

func (f *fabric) bind(at string, peers ...path.Peer) *rawBind {
	f.t.Helper()
	b := &rawBind{Bind: f.node(at).NewBind(), got: make(chan received, 1024)}
	if err := b.SetPeers(peers); err != nil {
		f.t.Fatal(err)
	}
	fns, port, err := b.Open(0)
	if err != nil {
		f.t.Fatal(err)
	}
	if port != 0 || len(fns) != 1 {
		f.t.Fatalf("Open reported port %d and %d receive funcs", port, len(fns))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		bufs := make([][]byte, b.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, path.MaxMessageSize)
		}
		sizes := make([]int, len(bufs))
		eps := make([]conn.Endpoint, len(bufs))
		for {
			n, err := fns[0](bufs, sizes, eps)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			for i := range n {
				b.got <- received{msg: bytes.Clone(bufs[i][:sizes[i]]), ep: eps[i]}
			}
		}
	}()
	f.t.Cleanup(func() {
		_ = b.Close()
		<-done
	})
	return b
}

func peer(name string, firstHops ...string) path.Peer {
	p := path.Peer{ID: id(name)}
	for _, h := range firstHops {
		p.FirstHops = append(p.FirstHops, id(h))
	}
	return p
}

func (b *rawBind) endpoint(t *testing.T, name string) conn.Endpoint {
	t.Helper()
	ep, err := b.ParseEndpoint(hexID(name))
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func (b *rawBind) send(t *testing.T, ep conn.Endpoint, msg string) {
	t.Helper()
	if err := b.Send([][]byte{wgMsg(msg)}, ep); err != nil {
		t.Fatalf("send %q: %v", msg, err)
	}
}

func (b *rawBind) current(peer string) string {
	hop, _, ok := b.Current(id(peer))
	if !ok {
		return ""
	}
	return string(trimID(hop))
}

func trimID(id path.NodeID) []byte { return bytes.TrimRight(id[:], "\x00") }

func (b *rawBind) expect(t *testing.T, msg string) received {
	t.Helper()
	select {
	case r := <-b.got:
		if tagOf(r.msg) != msg {
			t.Fatalf("got %q, want %q", tagOf(r.msg), msg)
		}
		return r
	case <-time.After(wait):
		t.Fatalf("%q never arrived", msg)
	}
	return received{}
}

// await waits for msg, passing over anything else still in flight.
func (b *rawBind) await(t *testing.T, msg string) received {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case r := <-b.got:
			if tagOf(r.msg) == msg {
				return r
			}
		case <-deadline:
			t.Fatalf("%q never arrived", msg)
		}
	}
}

func (b *rawBind) expectNothing(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case r := <-b.got:
		t.Fatalf("got %q, want nothing", tagOf(r.msg))
	case <-time.After(within):
	}
}

// drain empties what arrived so far and returns the last of it.
func (b *rawBind) drain() (received, bool) {
	var last received
	got := false
	for {
		select {
		case r := <-b.got:
			last, got = r, true
		default:
			return last, got
		}
	}
}

// keepSending sends msg every few milliseconds until it arrives.
func keepSending(t *testing.T, from, to *rawBind, ep conn.Endpoint, msg string) received {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		_ = from.Send([][]byte{wgMsg(msg)}, ep)
		select {
		case r := <-to.got:
			if tagOf(r.msg) == msg {
				return r
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("%q never arrived", msg)
	return received{}
}
