package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// loopbackOverlay stands in for the overlay under blob services on
// virtual TUNs: an overlay address a service listens on maps to a loopback
// listener, which the others dial by overlay address.
type loopbackOverlay struct {
	mu    sync.Mutex
	addrs map[netip.AddrPort]string
}

func (o *loopbackOverlay) listen(addr netip.AddrPort) (net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.addrs == nil {
		o.addrs = map[netip.AddrPort]string{}
	}
	o.addrs[addr] = l.Addr().String()
	return l, nil
}

func (o *loopbackOverlay) dial(ctx context.Context, _ netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	o.mu.Lock()
	real, ok := o.addrs[remote]
	o.mu.Unlock()
	if !ok {
		return nil, syscall.ECONNREFUSED
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", real)
}

var fastBlobs = blobs.Limits{RetryMin: 20 * time.Millisecond, RetryMax: 100 * time.Millisecond, ListenRetry: 20 * time.Millisecond,
	DialTimeout: time.Second, IdleTimeout: 2 * time.Second}

func (o *loopbackOverlay) service(store blobs.Store, log *slog.Logger) *blobs.Service {
	return blobs.New(blobs.Options{Store: store, Log: log, Listen: o.listen, Dial: o.dial, Limits: fastBlobs})
}

// Server a holds the list from its seed; device b, whose section names it,
// fetches it through the data plane's peers and keeps it in its state
// directory. The device serves nothing. When b is removed from the space
// it drops the list, on disk too.
func TestTheDataPlaneFetchesAndKeepsBlobs(t *testing.T) {
	s := newTestSpace(t)
	data, ref := s.withList(t, "ru", "192.0.2.0/24", "2001:db8::/32")
	for _, text := range []string{"geoip:ru -> direct", "default -> block"} {
		r, err := netmap.ParseRule(text)
		if err != nil {
			t.Fatal(err)
		}
		s.deviceRules = append(s.deviceRules, r)
	}
	_, reg := memoryRegistry(t)
	var ov loopbackOverlay

	seeds := worker.NewSeeds()
	seeds.Add(data)
	a := newRunningNode()
	dpA := a.dataPlane(reg, s.a, s.verified(t, 1))
	dpA.Blobs = ov.service(seedStore{seeds}, dpA.Log)
	a.run(t, dpA)

	stateB := s.stateDir(t, s.b, 1)
	b := newRunningNode()
	dpB := b.dataPlane(reg, s.b, s.verified(t, 1))
	dpB.Blobs = ov.service(diskBlobs{dir: stateB, log: dpB.Log}, dpB.Log)
	var engineB atomic.Pointer[dataplane.Engine]
	dpB.onEngine = func(e *dataplane.Engine) { engineB.Store(e) }
	b.run(t, dpB)

	eventually(t, func() bool { _, ok := dpB.Blobs.Get(ref.SHA256); return ok })
	// The rules take the list as it arrives.
	eventually(t, func() bool {
		e := engineB.Load()
		return e != nil && e.Status().Rules.Direct4 == 1 && e.Status().Rules.Direct6 == 1
	})
	if r, got, ok := dpB.Blobs.Latest(netmap.BlobGeoIP, "ru"); !ok || r != ref || !bytes.Equal(got, data) {
		t.Errorf("device: Latest(geoip, ru) = %v, %v", r, ok)
	}
	if st := dpB.Blobs.Status(); st.Fetched != 1 || st.Wanted != 1 {
		t.Errorf("device: %+v", st)
	}
	if st := dpA.Blobs.Status(); st.Loaded != 1 || st.Served != 1 {
		t.Errorf("server: %+v", st)
	}
	eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(stateB, BlobDir, blobFileName(ref.SHA256)))
		return err == nil
	})
	b4, b6 := overlay(2)
	ov.mu.Lock()
	for addr := range ov.addrs {
		if addr.Addr() == b4 || addr.Addr() == b6 {
			t.Errorf("the device listens on %v", addr)
		}
	}
	ov.mu.Unlock()

	without := s.buildWithout(t, 2, s.b)
	b.maps <- without
	b.waitLog(t, "removed from space")
	eventually(t, func() bool { st := dpB.Blobs.Status(); return st.Wanted == 0 && st.Held == 0 })
	eventually(t, func() bool { _, err := os.Lstat(filepath.Join(stateB, BlobDir)); return os.IsNotExist(err) })
}

func TestDiskBlobs(t *testing.T) {
	s := newTestSpace(t)
	ru, ruRef := s.withList(t, "ru", "192.0.2.0/24")
	de, deRef := s.withList(t, "de", "198.51.100.0/24")
	dir := s.stateDir(t, s.b, 1)
	d := diskBlobs{dir: dir, log: slog.New(slog.DiscardHandler)}

	if got := d.Load(ruRef); got != nil {
		t.Fatalf("an empty store loaded %d bytes", len(got))
	}
	if err := d.Prune(nil); err != nil {
		t.Fatalf("pruning nothing: %v", err)
	}
	for _, b := range []struct {
		ref  netmap.BlobRef
		data []byte
	}{{ruRef, ru}, {deRef, de}} {
		if err := d.Save(b.ref, b.data); err != nil {
			t.Fatal(err)
		}
		if got := d.Load(b.ref); !bytes.Equal(got, b.data) {
			t.Fatalf("loaded %x", got)
		}
	}
	// The state directory takes it as the node's own.
	st, err := LoadState(dir, filepath.Join(dir, MapFileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Unexpected) != 0 {
		t.Errorf("unexpected entries %v", st.Unexpected)
	}

	// Prune keeps what it is told and leaves what isn't a blob alone.
	bd := filepath.Join(dir, BlobDir)
	writeFile(t, filepath.Join(bd, "README"), []byte("x"), 0o600)
	writeFile(t, filepath.Join(bd, "."+blobFileName(deRef.SHA256)+".tmp"), []byte("x"), 0o600)
	if err := d.Prune([]netmap.BlobRef{ruRef}); err != nil {
		t.Fatal(err)
	}
	if got := names(t, bd); !slices.Equal(got, []string{blobFileName(ruRef.SHA256), "README", blobIndexFile}) {
		t.Errorf("after pruning: %v", got)
	}
	_ = os.Remove(filepath.Join(bd, "README"))
	// The last blob takes the directory with it.
	if err := d.Prune(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(bd); !os.IsNotExist(err) {
		t.Errorf("%s left: %v", bd, err)
	}
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestSeedBlobs(t *testing.T) {
	s := newTestSpace(t)
	ru, _ := s.withList(t, "ru", "192.0.2.0/24")
	de, _ := s.withList(t, "de", "198.51.100.0/24")
	_, _ = s.withList(t, "by", "203.0.113.0/24") // not seeded
	dir := s.stateDir(t, s.a, 1)
	if got := seedBlobs(dir, s.blobs, slog.New(slog.DiscardHandler)); got != nil {
		t.Fatalf("seeds without a blobs directory: %d", len(got))
	}
	bd := filepath.Join(dir, BlobDir)
	if err := os.Mkdir(bd, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(bd, blobFileName(s.blobs[0].SHA256)), ru, 0o600)
	tampered := bytes.Clone(de)
	tampered[len(tampered)-1] ^= 1
	writeFile(t, filepath.Join(bd, blobFileName(s.blobs[1].SHA256)), tampered, 0o600)
	var logs bytes.Buffer
	got := seedBlobs(dir, s.blobs, slog.New(slog.NewTextHandler(&logs, nil)))
	if len(got) != 1 || !bytes.Equal(got[0], ru) {
		t.Fatalf("seeds %d; want ru alone", len(got))
	}
	if !bytes.Contains(logs.Bytes(), []byte("a seeded blob doesn't match the map")) {
		t.Errorf("no warning about the tampered seed:\n%s", &logs)
	}
}

// A server's supervisor reads the seeds of the map's blobs from the state
// directory only when it sends them; the worker serves them from memory.
func TestServerSeedsItsWorker(t *testing.T) {
	s := newTestSpace(t)
	ru, ref := s.withList(t, "ru", "192.0.2.0/24")
	dir := s.stateDir(t, s.a, 1)
	if err := os.Mkdir(filepath.Join(dir, BlobDir), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, BlobDir, blobFileName(ref.SHA256)), ru, 0o600)

	sup := &fakeSupervisor{}
	r := runServerSpacesIn(t, s, sup, dir)
	eventually(t, func() bool { _, _, n := sup.last(); return n >= 1 })
	sp, _, _ := sup.last()
	if sp[0].Seeds == nil {
		t.Fatal("no seeds for the worker")
	}
	got := sp[0].Seeds()
	if len(got) != 1 || !bytes.Equal(got[0], ru) {
		t.Fatalf("the worker's seeds: %d", len(got))
	}
	if bytes.Contains(sp[0].Config, ru) || bytes.Contains(sp[0].Config, []byte(base64.StdEncoding.EncodeToString(ru))) {
		t.Error("the seed rides in the worker's config")
	}

	// The worker serves the seed: device b, without the list, gets it.
	_, reg := memoryRegistry(t)
	var ov loopbackOverlay
	w := newRunningNode()
	base := w.dataPlane(reg, NodeKeys{}, nil)
	base.blobOptions = blobs.Options{Listen: ov.listen, Dial: ov.dial, Limits: fastBlobs}
	sess := newFakeSession(s.id)
	sess.Seeds = worker.NewSeeds()
	sess.Seeds.Add(ru)
	sess.config <- sp[0].Config
	served := make(chan error, 1)
	go func() { served <- serveSpace(base.Log, base)(w.ctx, sess.Session) }()
	t.Cleanup(func() {
		w.stop()
		<-served
		if t.Failed() {
			t.Logf("worker log:\n%s", w.log)
		}
	})

	b := newRunningNode()
	dpB := b.dataPlane(reg, s.b, s.verified(t, 1))
	dpB.Blobs = ov.service(nil, dpB.Log)
	b.run(t, dpB)
	eventually(t, func() bool { _, ok := dpB.Blobs.Get(ref.SHA256); return ok })
	w.waitLog(t, `msg="blob loaded"`)
	_ = r
}

// Map v1 named ru = A, which the device stored; v2 names ru = B. Restarted
// without peers, the device uses A until B is verified.
func TestAStoredListOutlivesARestartUntilItsSuccessorArrives(t *testing.T) {
	s := newTestSpace(t)
	a, refA := s.withList(t, "ru", "192.0.2.0/24")
	_, refB := s.withList(t, "ru-next", "198.51.100.0/24")
	refB.Name = "ru"
	dir := s.stateDir(t, s.b, 1)
	d := diskBlobs{dir: dir, log: slog.New(slog.DiscardHandler)}
	if err := d.Save(refA, a); err != nil {
		t.Fatal(err)
	}
	if got := d.Index(); len(got) != 1 || got[0] != refA {
		t.Fatalf("index %+v", got)
	}

	var ov loopbackOverlay
	svc := ov.service(d, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.Run(ctx) }()
	defer func() { cancel(); <-done }()
	svc.Update(blobs.Plan{Want: []netmap.BlobRef{refB}})
	eventually(t, func() bool { r, _, ok := svc.Latest(netmap.BlobGeoIP, "ru"); return ok && r == refA })
	time.Sleep(100 * time.Millisecond)
	if got := d.Load(refA); !bytes.Equal(got, a) {
		t.Fatal("A pruned before B arrived")
	}

	// A torn index line costs that line only.
	writeFile(t, filepath.Join(dir, BlobDir, blobIndexFile), append([]byte("junk\n1 bad name 00 1\n"), encodeBlobIndex([]netmap.BlobRef{refA})...), 0o600)
	if got := d.Index(); len(got) != 1 || got[0] != refA {
		t.Fatalf("index %+v", got)
	}
}
