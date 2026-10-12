package blobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// testNet stands in for the overlay: services "listen" on overlay
// addresses, which map to loopback listeners, and dial them by overlay
// address.
type testNet struct {
	mu    sync.Mutex
	addrs map[netip.AddrPort]string
	src   sources
}

func newTestNet() *testNet { return &testNet{addrs: map[netip.AddrPort]string{}} }

func (n *testNet) listen(addr netip.AddrPort) (net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.addrs[addr] = l.Addr().String()
	return overlayListener{Listener: l, src: &n.src}, nil
}

// fake makes a raw server at addr that handles each connection with h.
func (n *testNet) fake(t *testing.T, addr netip.AddrPort, h func(c net.Conn)) {
	t.Helper()
	l, err := n.listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); h(c) }()
		}
	}()
}

func (n *testNet) dial(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	n.mu.Lock()
	real, ok := n.addrs[remote]
	n.mu.Unlock()
	if !ok {
		return nil, syscall.ECONNREFUSED
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", real)
	if err == nil && local.IsValid() {
		n.src.note(c, local)
	}
	return c, err
}

// memStore is a Store in memory that records what it was asked.
type memStore struct {
	mu     sync.Mutex
	blobs  map[[32]byte][]byte
	index  map[[32]byte]netmap.BlobRef
	saves  int
	prunes int
}

func newMemStore(blobs ...[]byte) *memStore {
	s := &memStore{blobs: map[[32]byte][]byte{}, index: map[[32]byte]netmap.BlobRef{}}
	for _, b := range blobs {
		s.blobs[sha256.Sum256(b)] = b
	}
	return s
}

func (s *memStore) Index() []netmap.BlobRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netmap.BlobRef
	for sha, ref := range s.index {
		if _, ok := s.blobs[sha]; ok {
			out = append(out, ref)
		}
	}
	return out
}

func (s *memStore) Load(ref netmap.BlobRef) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blobs[ref.SHA256]
}

func (s *memStore) Save(ref netmap.BlobRef, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[ref.SHA256] = data
	if s.index == nil {
		s.index = map[[32]byte]netmap.BlobRef{}
	}
	s.index[ref.SHA256] = ref
	s.saves++
	return nil
}

func (s *memStore) Prune(keep []netmap.BlobRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunes++
	kept := map[[32]byte][]byte{}
	index := map[[32]byte]netmap.BlobRef{}
	for _, r := range keep {
		if b, ok := s.blobs[r.SHA256]; ok {
			kept[r.SHA256] = b
			index[r.SHA256] = r
		}
	}
	s.blobs, s.index = kept, index
	return nil
}

func (s *memStore) has(ref netmap.BlobRef) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.blobs[ref.SHA256]
	return ok
}

// geoip makes a list blob holding the given prefixes, and its reference.
func geoip(t *testing.T, name string, prefixes ...string) ([]byte, netmap.BlobRef) {
	t.Helper()
	var b lists.Builder
	for _, p := range prefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	set, _ := b.Build()
	data := set.Blob()
	return data, refOf(netmap.BlobGeoIP, name, data)
}

func refOf(kind netmap.BlobKind, name string, data []byte) netmap.BlobRef {
	return netmap.BlobRef{Kind: kind, SHA256: sha256.Sum256(data), Size: uint64(len(data)), Name: name}
}

var fast = Limits{RetryMin: 20 * time.Millisecond, RetryMax: 100 * time.Millisecond, ListenRetry: 20 * time.Millisecond,
	DialTimeout: time.Second, IdleTimeout: 2 * time.Second}

// logBuffer collects a service's log lines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type node struct {
	*Service
	addr netip.Addr
	log  *logBuffer
}

func overlay(n byte) netip.Addr { return netip.AddrFrom4([4]byte{100, 64, 0, n}) }

func startNode(t *testing.T, tn *testNet, n byte, store Store, limits Limits) node {
	t.Helper()
	logs := &logBuffer{}
	s := New(Options{
		Store: store, Limits: limits, Listen: tn.listen, Dial: tn.dial,
		Log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("log of %v:\n%s", overlay(n), logs)
		}
	})
	return node{Service: s, addr: overlay(n), log: logs}
}

// plan is a server's plan: it listens, and fetches from peers in order.
// Every other test address (100.64.0.1-9) is a peer too, after them: the
// nodes that fetch from it.
func (n node) plan(want []netmap.BlobRef, peers ...node) Plan {
	p := Plan{Want: want, Local: []netip.Addr{n.addr}, Listen: []netip.Addr{n.addr}}
	listed := map[netip.Addr]bool{n.addr: true}
	for _, peer := range peers {
		p.Peers = append(p.Peers, Peer{ID: netmap.NodeID{peer.addr.As4()[3]}, Addrs: []netip.Addr{peer.addr}})
		listed[peer.addr] = true
	}
	for i := byte(1); i <= 9; i++ {
		if a := overlay(i); !listed[a] {
			p.Peers = append(p.Peers, Peer{ID: netmap.NodeID{i}, Addrs: []netip.Addr{a}})
		}
	}
	return p
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestADeviceFetchesItsListFromAServer(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24", "2001:db8::/32")
	header := ref
	header.Name = ""
	tn := newTestNet()
	server := startNode(t, tn, 1, newMemStore(data), fast)
	server.Update(server.plan([]netmap.BlobRef{header}))
	store := newMemStore()
	device := startNode(t, tn, 2, store, fast)
	device.Update(device.plan([]netmap.BlobRef{ref}, server))

	eventually(t, "the device holding the list", func() bool { _, ok := device.Get(ref.SHA256); return ok })
	got, _ := device.Get(ref.SHA256)
	if !bytes.Equal(got, data) {
		t.Fatal("the device holds other bytes")
	}
	if r, b, ok := device.Latest(netmap.BlobGeoIP, "ru"); !ok || r != ref || !bytes.Equal(b, data) {
		t.Fatalf("Latest(geoip, ru) = %v, %v", r, ok)
	}
	eventually(t, "the list stored", func() bool { return store.has(ref) })
	if st := device.Status(); st.Fetched != 1 || st.Held != 1 || st.Wanted != 1 || st.Rejected != 0 {
		t.Errorf("device status %+v", st)
	}
	eventually(t, "the server counting it", func() bool { return server.Status().Served == 1 })
	if st := server.Status(); st.Loaded != 1 || st.ServedBytes != ref.Size {
		t.Errorf("server status %+v", st)
	}
	if !strings.Contains(device.log.String(), `msg="blob fetched"`) {
		t.Errorf("no fetch in the log:\n%s", device.log)
	}
}

// tamperingPeer answers every request with a blob of the right size and
// the wrong bytes.
func tamperingPeer(t *testing.T, tn *testNet, at netip.Addr, size int, served *sync.WaitGroup) {
	tn.fake(t, netip.AddrPortFrom(at, Port), func(c net.Conn) {
		var req [requestSize]byte
		if _, err := io.ReadFull(c, req[:]); err != nil {
			return
		}
		head := [responseHeaderSize]byte{byte(statusOK)}
		binary.BigEndian.PutUint64(head[1:], uint64(size))
		_, _ = c.Write(head[:])
		_, _ = c.Write(bytes.Repeat([]byte{0x5a}, size))
		if served != nil {
			served.Done()
		}
	})
}

func TestATamperedBlobIsRejectedAndFetchedFromAnotherPeer(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	tn := newTestNet()
	var tampered sync.WaitGroup
	tampered.Add(1)
	tamperingPeer(t, tn, overlay(3), len(data), &tampered)
	good := startNode(t, tn, 1, newMemStore(data), fast)
	good.Update(good.plan([]netmap.BlobRef{ref}))
	store := newMemStore()
	device := startNode(t, tn, 2, store, fast)
	bad := node{addr: overlay(3)}
	device.Update(device.plan([]netmap.BlobRef{ref}, bad, good)) // the tampering peer first

	eventually(t, "the device holding the list", func() bool { _, ok := device.Get(ref.SHA256); return ok })
	tampered.Wait()
	got, _ := device.Get(ref.SHA256)
	if !bytes.Equal(got, data) {
		t.Fatal("the device holds the tampered bytes")
	}
	if st := device.Status(); st.Rejected != 1 || st.Fetched != 1 {
		t.Errorf("status %+v", st)
	}
	if b := store.Load(ref); !bytes.Equal(b, data) {
		t.Error("the store has other bytes")
	}
	if !strings.Contains(device.log.String(), `msg="blob rejected: the peer sent something else; trying another peer"`) {
		t.Errorf("no rejection in the log:\n%s", device.log)
	}
}

func TestATamperedStoredBlobIsReplaced(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	tampered := bytes.Clone(data)
	tampered[len(tampered)-1] ^= 1
	tn := newTestNet()
	server := startNode(t, tn, 1, newMemStore(data), fast)
	server.Update(server.plan([]netmap.BlobRef{ref}))
	store := &memStore{blobs: map[[32]byte][]byte{ref.SHA256: tampered}}
	device := startNode(t, tn, 2, store, fast)
	device.Update(device.plan([]netmap.BlobRef{ref}, server))

	eventually(t, "the device holding the list", func() bool { _, ok := device.Get(ref.SHA256); return ok })
	if st := device.Status(); st.StoreRejected != 1 || st.Fetched != 1 || st.Loaded != 0 {
		t.Errorf("status %+v", st)
	}
	eventually(t, "the store repaired", func() bool { return bytes.Equal(store.Load(ref), data) })
}

func TestABlobInTheStoreNeedsNoPeer(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	tn := newTestNet()
	device := startNode(t, tn, 2, newMemStore(data), fast)
	device.Update(device.plan([]netmap.BlobRef{ref}))
	eventually(t, "the device holding the list", func() bool { _, ok := device.Get(ref.SHA256); return ok })
	if st := device.Status(); st.Loaded != 1 || st.Fetched != 0 {
		t.Errorf("status %+v", st)
	}
}

func TestTheFormerListServesUntilItsSuccessorIsVerified(t *testing.T) {
	v1, ref1 := geoip(t, "ru", "192.0.2.0/24")
	v2, ref2 := geoip(t, "ru", "198.51.100.0/24")
	tn := newTestNet()
	store := newMemStore(v1)
	device := startNode(t, tn, 2, store, fast)
	device.Update(device.plan([]netmap.BlobRef{ref1}))
	eventually(t, "v1 held", func() bool { _, ok := device.Get(ref1.SHA256); return ok })

	// A new map moves to v2, which no peer has yet.
	server := startNode(t, tn, 1, newMemStore(), fast)
	server.Update(server.plan(nil))
	device.Update(device.plan([]netmap.BlobRef{ref2}, server))
	time.Sleep(100 * time.Millisecond) // a few failed rounds
	if r, b, ok := device.Latest(netmap.BlobGeoIP, "ru"); !ok || r != ref1 || !bytes.Equal(b, v1) {
		t.Fatalf("while v2 is missing, Latest(geoip, ru) = %v, %v; want v1", r, ok)
	}
	if !store.has(ref1) {
		t.Fatal("v1 was pruned from the store before v2 arrived")
	}
	// A peer that answers v1 requests still gets it: the device holds it.
	if _, ok := device.Get(ref1.SHA256); !ok {
		t.Fatal("v1 not held")
	}

	// The server gets v2 (from its own store), the device fetches it.
	server2 := startNode(t, tn, 3, newMemStore(v2), fast)
	server2.Update(server2.plan([]netmap.BlobRef{ref2}))
	device.Update(device.plan([]netmap.BlobRef{ref2}, server, server2))
	eventually(t, "v2 held", func() bool { _, ok := device.Get(ref2.SHA256); return ok })
	if r, _, ok := device.Latest(netmap.BlobGeoIP, "ru"); !ok || r != ref2 {
		t.Fatalf("Latest(geoip, ru) = %v, %v; want v2", r, ok)
	}
	eventually(t, "v1 dropped", func() bool { _, ok := device.Get(ref1.SHA256); return !ok && !store.has(ref1) })
	if !store.has(ref2) {
		t.Error("v2 not stored")
	}
}

func TestAServerHoldsTheWholeAvailabilitySetAndPassesItOn(t *testing.T) {
	ru, ruRef := geoip(t, "", "192.0.2.0/24")
	de, deRef := geoip(t, "", "198.51.100.0/24")
	other := []byte("a blob of a kind this node doesn't read")
	otherRef := refOf(netmap.BlobKind(9), "", other)
	set := []netmap.BlobRef{ruRef, deRef, otherRef}
	tn := newTestNet()
	seed := startNode(t, tn, 1, newMemStore(ru, de, other), fast)
	seed.Update(seed.plan(set))
	relay := startNode(t, tn, 2, nil, fast)
	relay.Update(relay.plan(set, seed))
	device := startNode(t, tn, 3, nil, fast)
	named := deRef
	named.Name = "de"
	device.Update(device.plan([]netmap.BlobRef{named}, relay)) // reaches only the relay
	eventually(t, "the relay holding the set", func() bool { return relay.Status().Held == 3 })
	eventually(t, "the device holding its list", func() bool { _, ok := device.Get(deRef.SHA256); return ok })
	if st := device.Status(); st.Wanted != 1 || st.Held != 1 {
		t.Errorf("device status %+v", st)
	}
}

func TestNothingIsServedThatIsNotHeld(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	_, unknown := geoip(t, "de", "198.51.100.0/24")
	tn := newTestNet()
	server := startNode(t, tn, 1, newMemStore(data), fast)
	server.Update(server.plan([]netmap.BlobRef{ref}))
	eventually(t, "the server holding the list", func() bool { _, ok := server.Get(ref.SHA256); return ok })

	ask := func(req []byte) []byte {
		t.Helper()
		c, err := tn.dial(context.Background(), overlay(9), netip.AddrPortFrom(server.addr, Port))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(c)
		return b
	}
	r := request{sha256: unknown.SHA256}.encode()
	if got := ask(r[:]); !bytes.Equal(got, []byte{byte(statusNotHere)}) {
		t.Errorf("unknown blob: %x", got)
	}
	r = request{sha256: ref.SHA256, offset: ref.Size + 1}.encode()
	if got := ask(r[:]); !bytes.Equal(got, []byte{byte(statusBadRequest)}) {
		t.Errorf("offset past the end: %x", got)
	}
	r = request{sha256: ref.SHA256}.encode()
	r[3] = 2 // another version
	if got := ask(r[:]); !bytes.Equal(got, []byte{byte(statusBadRequest)}) {
		t.Errorf("other version: %x", got)
	}
	r = request{sha256: ref.SHA256, offset: 10}.encode()
	got := ask(r[:])
	if len(got) != responseHeaderSize+len(data)-10 || got[0] != byte(statusOK) ||
		binary.BigEndian.Uint64(got[1:9]) != ref.Size-10 || !bytes.Equal(got[9:], data[10:]) {
		t.Errorf("from offset 10: %x", got)
	}
	if st := server.Status(); st.NotHere != 1 {
		t.Errorf("status %+v", st)
	}

	// A device asking for what the server doesn't hold doesn't get it.
	device := startNode(t, tn, 2, nil, fast)
	device.Update(device.plan([]netmap.BlobRef{unknown}, server))
	time.Sleep(100 * time.Millisecond)
	if st := device.Status(); st.Held != 0 || st.Rejected != 0 {
		t.Errorf("device status %+v", st)
	}
}

func TestABrokenTransferResumes(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32", "2001:db8:1::/48")
	tn := newTestNet()
	var mu sync.Mutex
	var offsets []uint64
	tn.fake(t, netip.AddrPortFrom(overlay(1), Port), func(c net.Conn) {
		var b [requestSize]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		req, err := decodeRequest(b)
		if err != nil {
			return
		}
		mu.Lock()
		offsets = append(offsets, req.offset)
		first := len(offsets) == 1
		mu.Unlock()
		head := [responseHeaderSize]byte{byte(statusOK)}
		binary.BigEndian.PutUint64(head[1:], uint64(len(data))-req.offset)
		_, _ = c.Write(head[:])
		rest := data[req.offset:]
		if first {
			rest = rest[:len(rest)/2] // and hang up
		}
		_, _ = c.Write(rest)
	})
	device := startNode(t, tn, 2, nil, fast)
	device.Update(device.plan([]netmap.BlobRef{ref}, node{addr: overlay(1)}))
	eventually(t, "the device holding the list", func() bool { _, ok := device.Get(ref.SHA256); return ok })
	mu.Lock()
	defer mu.Unlock()
	if len(offsets) != 2 || offsets[0] != 0 || offsets[1] != uint64(len(data)/2) {
		t.Errorf("requests from offsets %v; want 0 then %d", offsets, len(data)/2)
	}
}

func TestAPeerAnnouncingTheWrongLengthIsRejected(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	tn := newTestNet()
	tn.fake(t, netip.AddrPortFrom(overlay(1), Port), func(c net.Conn) {
		var b [requestSize]byte
		_, _ = io.ReadFull(c, b[:])
		head := [responseHeaderSize]byte{byte(statusOK)}
		binary.BigEndian.PutUint64(head[1:], 1<<40) // far more than the blob
		_, _ = c.Write(head[:])
		_, _ = c.Write(data)
	})
	device := startNode(t, tn, 2, nil, fast)
	device.Update(device.plan([]netmap.BlobRef{ref}, node{addr: overlay(1)}))
	eventually(t, "a rejection", func() bool { return device.Status().Rejected > 0 })
	if _, ok := device.Get(ref.SHA256); ok {
		t.Error("held a blob from a peer that broke the protocol")
	}
}

func TestBlobsOverTheLimitsAreSkipped(t *testing.T) {
	small, smallRef := geoip(t, "a", "192.0.2.0/24")
	_, bigRef := geoip(t, "b", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
	limits := fast
	limits.MaxBlob = int64(bigRef.Size - 1)
	limits.MaxHeld = int64(smallRef.Size)
	tn := newTestNet()
	device := startNode(t, tn, 2, newMemStore(small), limits)
	_, otherRef := geoip(t, "c", "192.0.2.0/25")
	device.Update(device.plan([]netmap.BlobRef{smallRef, bigRef, otherRef}))
	eventually(t, "the small list held", func() bool { _, ok := device.Get(smallRef.SHA256); return ok })
	if st := device.Status(); st.Skipped != 2 || st.Wanted != 1 {
		t.Errorf("status %+v; want b over the per-blob limit and c over the total", st)
	}
}

func TestAMapNamingABadListIsNotRetried(t *testing.T) {
	junk := []byte("not a list")
	ref := refOf(netmap.BlobGeoIP, "ru", junk)
	tn := newTestNet()
	store := newMemStore(junk)
	device := startNode(t, tn, 2, store, fast)
	device.Update(device.plan([]netmap.BlobRef{ref}))
	eventually(t, "the list failed", func() bool { return device.Status().Failed == 1 })
	if _, ok := device.Get(ref.SHA256); ok {
		t.Error("held a list that doesn't decode")
	}
}

func TestBusyPastThePerPeerLimit(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32")
	limits := fast
	limits.MaxConnsPerPeer = 1
	tn := newTestNet()
	server := startNode(t, tn, 1, newMemStore(data), limits)
	server.Update(server.plan([]netmap.BlobRef{ref}))
	eventually(t, "the server holding the list", func() bool { _, ok := server.Get(ref.SHA256); return ok })

	// One connection that never sends its request holds the peer's slot.
	hold, err := tn.dial(context.Background(), overlay(9), netip.AddrPortFrom(server.addr, Port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	eventually(t, "the slot taken", func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return server.nconns == 1
	})
	c, err := tn.dial(context.Background(), overlay(9), netip.AddrPortFrom(server.addr, Port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(c)
	if !bytes.Equal(b, []byte{byte(statusBusy)}) {
		t.Errorf("second connection got %x; want busy", b)
	}
	if st := server.Status(); st.Busy != 1 {
		t.Errorf("status %+v", st)
	}
}

func TestServingIsRateLimited(t *testing.T) {
	l := newLimiter(1<<20, time.Now)
	start := time.Now()
	for range 4 {
		if err := l.wait(context.Background(), 64<<10); err != nil {
			t.Fatal(err)
		}
	}
	// One burst is free, the other three take 64 KiB / 1 MiB/s each.
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("256 KiB at 1 MiB/s took %v", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.wait(ctx, 1<<20); !errors.Is(err, context.Canceled) {
		t.Errorf("wait on a cancelled context: %v", err)
	}
}

func TestCheck(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	if err := Check(ref, data); err != nil {
		t.Errorf("good blob: %v", err)
	}
	for name, c := range map[string]struct {
		ref  netmap.BlobRef
		data []byte
		want error
	}{
		"short":         {ref, data[:len(data)-1], ErrMismatch},
		"flipped":       {ref, append(bytes.Clone(data[:len(data)-1]), data[len(data)-1]^1), ErrMismatch},
		"bad list":      {refOf(netmap.BlobGeoIP, "x", []byte("junk")), []byte("junk"), ErrUndecodable},
		"unknown kind":  {refOf(netmap.BlobKind(7), "", []byte("junk")), []byte("junk"), nil},
		"geosite bytes": {refOf(netmap.BlobGeoSite, "", []byte("junk")), []byte("junk"), nil},
	} {
		if err := Check(c.ref, c.data); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestStatusQuotesNothing(t *testing.T) {
	_, ref := geoip(t, "ru", "192.0.2.0/24")
	s := New(Options{})
	s.Update(Plan{Want: []netmap.BlobRef{ref}, Local: []netip.Addr{overlay(1)}, Listen: []netip.Addr{overlay(1)}, Peers: []Peer{{Addrs: []netip.Addr{overlay(2)}}}})
	out := fmt.Sprintf("%+v", s.Status())
	for _, leak := range []string{"100.64", "ru", fmt.Sprintf("%x", ref.SHA256[:4])} {
		if strings.Contains(out, leak) {
			t.Errorf("status %s quotes %q", out, leak)
		}
	}
}

// Through the tunnel every source is a peer's overlay address; a
// connection from anything else gets nothing at all.
func TestOnlyPeersAreServed(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	tn := newTestNet()
	server := startNode(t, tn, 1, newMemStore(data), fast)
	p := server.plan([]netmap.BlobRef{ref})
	p.Peers = nil
	server.Update(p)
	eventually(t, "the server holding the list", func() bool { _, ok := server.Get(ref.SHA256); return ok })
	for _, local := range []netip.Addr{overlay(2), {}} {
		c, err := tn.dial(context.Background(), local, netip.AddrPortFrom(server.addr, Port))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		req := request{sha256: ref.SHA256}.encode()
		_, _ = c.Write(req[:])
		if b, _ := io.ReadAll(c); len(b) != 0 {
			t.Errorf("from %v: %x", local, b)
		}
		_ = c.Close()
	}
	if st := server.Status(); st.NotPeer != 2 || st.Served != 0 {
		t.Errorf("status %+v", st)
	}
}
