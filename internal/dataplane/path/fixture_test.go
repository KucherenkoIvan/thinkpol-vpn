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

// Fast timings: a silent link is down after 150 ms.
var fastOptions = path.Options{
	ProbeInterval: 30 * time.Millisecond,
	DeadAfter:     150 * time.Millisecond,
	FollowFor:     150 * time.Millisecond,
	RedialMin:     10 * time.Millisecond,
	RedialMax:     100 * time.Millisecond,
	Selector:      path.Failover{HoldDown: 500 * time.Millisecond},
}

// wait bounds every wait for something that should happen.
const wait = 5 * time.Second

// eachSemantics runs a test over a datagram and a stream memory transport.
func eachSemantics(t *testing.T, test func(t *testing.T, f *fabric)) {
	for _, sem := range []memory.Semantics{memory.Datagram, memory.Stream} {
		t.Run(sem.String(), func(t *testing.T) {
			t.Parallel()
			test(t, newFabric(t, sem))
		})
	}
}

// fabric is a set of nodes on one memory network. Links can be silenced:
// their packets vanish in both directions without an error, as on a
// datagram transport whose far end died or a censor started dropping.
type fabric struct {
	t  *testing.T
	tr *memory.Network

	mu       sync.Mutex
	silenced map[string]bool // "from>to"
	nodes    map[string]*fnode
}

type fnode struct {
	*path.Node
	peers   *transport.PeerTable
	inbound []transport.PeerLink
	table   path.Table
}

func newFabric(t *testing.T, sem memory.Semantics) *fabric {
	return &fabric{t: t, tr: memory.NewNetwork(sem), silenced: map[string]bool{}, nodes: map[string]*fnode{}}
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
		n := &fnode{Node: path.NewNode(id(name), fastOptions), peers: transport.NewPeerTable()}
		l, err := f.tr.Listen(context.Background(), transport.ListenConfig{Address: name, Peers: n.peers})
		if err != nil {
			f.t.Fatal(err)
		}
		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = n.Serve(l)
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

// dial makes from keep a link to to, and waits until it is up.
func (f *fabric) dial(from, to string) {
	f.t.Helper()
	a, b := f.node(from), f.node(to)
	secret := []byte("secret " + from + ">" + to)
	b.inbound = append(b.inbound, transport.PeerLink{Peer: transport.Identity{Node: id(from)}, Verifier: secret})
	b.peers.Set(b.inbound)
	a.table.Links = append(a.table.Links, path.Link{Node: id(to), Endpoints: []path.Endpoint{{
		Dialer:  silenceable{f: f, key: from + ">" + to},
		Address: to,
		Config:  transport.DialConfig{Credential: secret},
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

func (f *fabric) silence(from, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.silenced[from+">"+to] = true
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

func (f *fabric) waitUp(at, of string) {
	f.t.Helper()
	eventually(f.t, at+" sees "+of+" up", func() bool {
		s, ok := f.neighbor(at, of)
		return ok && s.Up
	})
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// silenceable dials over the fabric's network; the links it opens go quiet
// once the fabric silences them.
type silenceable struct {
	f   *fabric
	key string
}

func (d silenceable) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	l, err := d.f.tr.Dial(ctx, endpoint, cfg)
	if err != nil {
		return nil, err
	}
	return &silenceableLink{Link: l, silenced: func() bool { return d.f.isSilenced(d.key) }}, nil
}

type silenceableLink struct {
	transport.Link
	silenced func() bool
}

func (l *silenceableLink) WritePacket(p []byte) error {
	if l.silenced() {
		return transport.CheckPacketSize(p)
	}
	return l.Link.WritePacket(p)
}

func (l *silenceableLink) ReadPacket(p []byte) (int, error) {
	for {
		n, err := l.Link.ReadPacket(p)
		if err != nil || !l.silenced() {
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
	b := &rawBind{Bind: f.node(at).NewBind(), got: make(chan received, 64)}
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
	if err := b.Send([][]byte{[]byte(msg)}, ep); err != nil {
		t.Fatalf("send %q: %v", msg, err)
	}
}

func (b *rawBind) expect(t *testing.T, msg string) received {
	t.Helper()
	select {
	case r := <-b.got:
		if string(r.msg) != msg {
			t.Fatalf("got %q, want %q", r.msg, msg)
		}
		return r
	case <-time.After(wait):
		t.Fatalf("%q never arrived", msg)
	}
	return received{}
}

func (b *rawBind) expectNothing(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case r := <-b.got:
		t.Fatalf("got %q, want nothing", r.msg)
	case <-time.After(within):
	}
}

// keepSending sends msg every few milliseconds until it arrives.
func keepSending(t *testing.T, from, to *rawBind, ep conn.Endpoint, msg string) received {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		_ = from.Send([][]byte{[]byte(msg)}, ep)
		select {
		case r := <-to.got:
			if string(r.msg) == msg {
				return r
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("%q never arrived", msg)
	return received{}
}
