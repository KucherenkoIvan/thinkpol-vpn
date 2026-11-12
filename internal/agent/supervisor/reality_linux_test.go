//go:build linux && !android

package supervisor_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/reality"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

const (
	envReality  = "SUPERVISOR_TEST_REALITY" // set: the worker serves reality behind the shared listener
	realityPort = 7444
	realityName = "www.example.net"
)

// realityServe is a worker's data plane reduced to its reality listeners
// behind the supervisor's shared listener, for the links its own map
// lists: it reports every link it accepts and every packet ("probe ..."
// lines) and answers each packet.
func realityServe(ctx context.Context, s worker.Session) error {
	say := func(format string, args ...any) { fmt.Fprintf(os.Stderr, "probe "+format+"\n", args...) }
	peers := transport.NewPeerTable()
	reg, err := transport.NewRegistry(reality.New(reality.Options{}))
	if err != nil {
		return err
	}
	serving := map[uint32]bool{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case b := <-s.Config:
			var c sharedConfig
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			peers.Set(c.Inbound)
			say("config links=%d", len(c.Inbound))
		case ls := <-s.Listeners:
			for _, l := range ls {
				if serving[l.ID] || !l.Stream || l.Transport != reality.Name {
					continue
				}
				serving[l.ID] = true
				tl, err := l.Listen(reg, transport.Admission{Peers: peers})
				if err != nil {
					say("listen failed: %v", err)
					return err
				}
				go acceptStreamLinks(ctx, tl, say)
			}
			say("listeners %d", len(serving))
		case <-s.SharedCounters:
		}
	}
}

func acceptStreamLinks(ctx context.Context, l transport.Listener, say func(string, ...any)) {
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
				say("packet %s %s", id, buf[:n])
				_ = link.WritePacket(append([]byte("reply "), buf[:n]...))
			}
		}()
	}
}

// realityTarget is a TLS 1.3 site on loopback, the listener's camouflage
// target: it records the raw bytes of every connection.
type realityTarget struct {
	ln    net.Listener
	roots *x509.CertPool

	mu    sync.Mutex
	conns []*bytes.Buffer
}

func startRealityTarget(t *testing.T) *realityTarget {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{realityName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	tg := &realityTarget{roots: x509.NewCertPool()}
	tg.roots.AddCert(leaf)
	if tg.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tg.ln.Close() })
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	go func() {
		for {
			c, err := tg.ln.Accept()
			if err != nil {
				return
			}
			buf := &bytes.Buffer{}
			tg.mu.Lock()
			tg.conns = append(tg.conns, buf)
			tg.mu.Unlock()
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				rc := recordingConn{Conn: c, mu: &tg.mu, buf: buf}
				_ = tls.Server(rc, cfg).Handshake()
				_, _ = io.Copy(io.Discard, rc) // whatever follows, recorded raw
			}()
		}
	}()
	return tg
}

type recordingConn struct {
	net.Conn
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (c recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.buf.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

// receivedWhole waits for a connection of the target's to have received
// exactly what stream returns (read again each time: a tap may still be
// passing its last bytes on).
func (tg *realityTarget) receivedWhole(stream func() []byte) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stream := stream()
		tg.mu.Lock()
		for _, b := range tg.conns {
			if len(stream) > 0 && bytes.Equal(b.Bytes(), stream) {
				tg.mu.Unlock()
				return true
			}
		}
		tg.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// streamTap passes one connection through to address and keeps what the
// dialer sent.
type streamTap struct {
	ln   net.Listener
	mu   sync.Mutex
	sent bytes.Buffer
}

func newStreamTap(t *testing.T, address string) *streamTap {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tp := &streamTap{ln: ln}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", address)
		if err != nil {
			_ = c.Close()
			return
		}
		go func() {
			_, _ = io.Copy(io.MultiWriter(up, writerFunc(func(p []byte) (int, error) {
				tp.mu.Lock()
				defer tp.mu.Unlock()
				return tp.sent.Write(p)
			})), c)
			_ = up.Close()
		}()
		_, _ = io.Copy(c, up)
		_ = c.Close()
	}()
	return tp
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func (tp *streamTap) captured() []byte {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return bytes.Clone(tp.sent.Bytes())
}

// realitySpace is a space whose hand-made map section lets dialers in over
// reality, each dialer's secret its short id.
func realitySpace(t *testing.T, reg *transport.Registry, dialers ...dialer) sharedSpace {
	t.Helper()
	sp := sharedSpace{ID: netmap.NewSpaceID(), Dialers: dialers}
	section := netmap.Section{Node: netmap.NodeSettings{ID: netmap.NodeID(randomBytes(8)), Kind: netmap.NodeServer, AllowIngress: true}}
	for _, d := range dialers {
		section.Inbound = append(section.Inbound, netmap.InboundLink{Peer: d.Node, PeerKind: netmap.NodeDevice, Transport: reality.Name, Credential: d.Secret})
	}
	in := dataplane.AcceptedInbound(section, reg, transport.SpaceID(sp.ID), 0)
	if len(in.Skipped) > 0 {
		t.Fatalf("skipped %v", in.Skipped)
	}
	config, err := json.Marshal(sharedConfig{Inbound: in.Links[reality.Name]})
	if err != nil {
		t.Fatal(err)
	}
	sp.Space = supervisor.Space{ID: sp.ID, Config: config, Inbound: in.Links}
	return sp
}

func newRealityDialer() dialer {
	return dialer{Node: netmap.NodeID(randomBytes(8)), Secret: randomBytes(reality.ShortIDSize)}
}

// TP-201's acceptance: two spaces on one server behind one reality
// listener. The short id selects the space, and the connection goes to
// that space's worker, which completes REALITY's handshake in its sandbox
// (with the target's records the supervisor learned) and carries packets
// both ways. A wrong short id and a replay are spliced to the target, raw
// and whole, and reach no worker.
func TestRealitySpacesShareAListener(t *testing.T) {
	needsLab(t)
	tg := startRealityTarget(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	listenSettings, err := proto.Marshal(&transportv1.RealityListenSettings{PrivateKey: key.Bytes(), Target: tg.ln.Addr().String(), ServerNames: []string{realityName}})
	if err != nil {
		t.Fatal(err)
	}
	dialSettings, err := proto.Marshal(&transportv1.RealityDialSettings{ServerName: realityName, PublicKey: key.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := transport.NewRegistry(reality.New(reality.Options{TrustTargetRoots: tg.roots}))
	if err != nil {
		t.Fatal(err)
	}
	a1, a2, b1 := newRealityDialer(), newRealityDialer(), newRealityDialer()
	spA, spB := realitySpace(t, reg, a1, a2), realitySpace(t, reg, b1)
	o := options([]string{envReality + "=1"})
	o.Transports = reg
	s, err := supervisor.New(o)
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
	if err := s.SetListeners([]supervisor.Listener{{Transport: reality.Name, Address: fmt.Sprintf("0.0.0.0:%d", realityPort), Settings: listenSettings}}); err != nil {
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
	public := fmt.Sprintf("127.0.0.1:%d", realityPort)
	rd := reality.New(reality.Options{})
	dial := func(address string, d dialer) (transport.Link, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		l, err := rd.Dial(ctx, address, transport.DialConfig{Credential: d.Secret, Settings: dialSettings})
		if err == nil {
			t.Cleanup(func() { _ = l.Close() })
		}
		return l, err
	}

	links := map[netmap.NodeID]transport.Link{}
	for _, sp := range []sharedSpace{spA, spB} {
		for _, d := range sp.Dialers {
			l, err := dial(public, d)
			if err != nil {
				t.Fatalf("dialer %s of space %s: %v; output %q", d.Node, sp.ID, err, s.Output(sp.ID))
			}
			links[d.Node] = l
			if err := l.WritePacket([]byte("hello from " + d.Node.String())); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, sp := range []sharedSpace{spA, spB} {
		for _, d := range sp.Dialers {
			id := transport.Identity{Space: transport.SpaceID(sp.ID), Node: transport.NodeID(d.Node)}
			eventually(t, 10*time.Second, "the link at its worker", func() error {
				if !hasLine(s, sp.ID, "accepted "+id.String()) || !hasLine(s, sp.ID, "packet "+id.String()+" hello from "+d.Node.String()) {
					return fmt.Errorf("output %q", probeLines(s, sp.ID))
				}
				return nil
			})
			got := make(chan string, 1)
			go func() {
				buf := make([]byte, 256)
				n, _ := links[d.Node].ReadPacket(buf)
				got <- string(buf[:n])
			}()
			select {
			case r := <-got:
				if r != "reply hello from "+d.Node.String() {
					t.Fatalf("dialer %s got %q", d.Node, r)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("no reply for dialer %s", d.Node)
			}
		}
	}

	// A wrong short id, through a tap: spliced whole, the dial fails on
	// the target's real certificate.
	wrong := newRealityDialer()
	tp := newStreamTap(t, public)
	if _, err := dial(tp.ln.Addr().String(), wrong); !errors.Is(err, reality.ErrNotAuthenticated) {
		t.Fatalf("a wrong short id: %v, want %v", err, reality.ErrNotAuthenticated)
	}
	if !tg.receivedWhole(tp.captured) {
		t.Error("the wrong short id's connection didn't reach the target raw and whole")
	}
	// A replay: a1's authenticated connection, captured and sent again.
	tp = newStreamTap(t, public)
	if _, err := dial(tp.ln.Addr().String(), a1); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "a1's second link", func() error {
		if n := strings.Count(strings.Join(probeLines(s, spA.ID), "\n"), "accepted "+transport.Identity{Space: transport.SpaceID(spA.ID), Node: transport.NodeID(a1.Node)}.String()); n != 2 {
			return fmt.Errorf("accepted %d times", n)
		}
		return nil
	})
	captured := tp.captured()
	replay, err := net.Dial("tcp", public)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replay.Close() }()
	if _, err := replay.Write(captured); err != nil {
		t.Fatal(err)
	}
	if !tg.receivedWhole(func() []byte { return captured }) {
		t.Error("the replay didn't reach the target raw and whole")
	}
	// The stranger counted on the listener, the replay as space A's.
	eventually(t, 5*time.Second, "the stranger and the replay counted", func() error {
		if ls := s.Listeners(); len(ls) != 1 || ls[0].Unauthenticated != 1 || ls[0].Routed != 4 {
			return fmt.Errorf("listeners %+v", ls)
		}
		for _, w := range s.Workers() {
			if w.Space == spA.ID && w.Shared.Replayed != 1 {
				return fmt.Errorf("space A %+v", w.Shared)
			}
		}
		return nil
	})

	// Each worker accepted exactly its own links (a1's twice).
	for _, sp := range []sharedSpace{spA, spB} {
		var accepted []string
		for _, l := range probeLines(s, sp.ID) {
			if rest, ok := strings.CutPrefix(l, "accepted "); ok {
				accepted = append(accepted, rest)
			}
		}
		want := len(sp.Dialers)
		if sp.ID == spA.ID {
			want++
		}
		if len(accepted) != want {
			t.Errorf("space %s accepted %q, want %d", sp.ID, accepted, want)
		}
		for _, id := range accepted {
			if !strings.HasPrefix(id, sp.ID.String()+"/") {
				t.Errorf("space %s accepted a link of %s", sp.ID, id)
			}
		}
	}
}
