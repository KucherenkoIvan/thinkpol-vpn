package blobs

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// tricklingPeer answers any request with the right header, then one byte
// every 50 ms, never faster: slow enough to be abandoned, steady enough
// never to hit the idle timeout. The channel gets a value for each
// transfer under way (header sent).
func tricklingPeer(t *testing.T, tn *testNet, at netip.Addr, size int) <-chan struct{} {
	started := make(chan struct{}, 16)
	tn.fake(t, netip.AddrPortFrom(at, Port), func(c net.Conn) {
		var req [requestSize]byte
		if _, err := io.ReadFull(c, req[:]); err != nil {
			return
		}
		head := [responseHeaderSize]byte{byte(statusOK)}
		binary.BigEndian.PutUint64(head[1:], uint64(size))
		if _, err := c.Write(head[:]); err != nil {
			return
		}
		select {
		case started <- struct{}{}:
		default:
		}
		for range size {
			time.Sleep(50 * time.Millisecond)
			if _, err := c.Write([]byte{0}); err != nil {
				return
			}
		}
	})
	return started
}

func TestATricklingPeerIsAbandoned(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32")
	tn := newTestNet()
	tricklingPeer(t, tn, overlay(3), len(data))
	good := startNode(t, tn, 1, newMemStore(data), fast)
	good.Update(good.plan([]netmap.BlobRef{ref}))
	limits := fast
	limits.DialTimeout = 300 * time.Millisecond
	limits.MinRate = 1 << 20 // the transfer gets 0.3 s and change
	device := startNode(t, tn, 2, nil, limits)
	start := time.Now()
	device.Update(device.plan([]netmap.BlobRef{ref}, node{addr: overlay(3)}, good))
	eventually(t, "the list from the good peer", func() bool { _, ok := device.Get(ref.SHA256); return ok })
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v behind a trickling peer", d)
	}
	if st := device.Status(); st.Abandoned != 1 || st.Fetched != 1 {
		t.Errorf("status %+v", st)
	}
}

func TestANewMapAbandonsAStalledTransfer(t *testing.T) {
	old, oldRef := geoip(t, "ru", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32")
	data, ref := geoip(t, "de", "203.0.113.0/24")
	tn := newTestNet()
	trickling := tricklingPeer(t, tn, overlay(3), len(old))
	good := startNode(t, tn, 1, newMemStore(data), fast)
	good.Update(good.plan([]netmap.BlobRef{ref}))
	limits := fast
	limits.MinRate = 1 // the trickle alone would hold the fetch for hours
	device := startNode(t, tn, 2, nil, limits)
	device.Update(device.plan([]netmap.BlobRef{oldRef}, node{addr: overlay(3)}))
	select { // the stalled transfer is under way
	case <-trickling:
	case <-time.After(5 * time.Second):
		t.Fatal("the device never asked the trickling peer")
	}
	start := time.Now()
	device.Update(device.plan([]netmap.BlobRef{ref}, good))
	eventually(t, "the new map's list", func() bool { _, ok := device.Get(ref.SHA256); return ok })
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("the new map waited %v for the stalled transfer", d)
	}
	if st := device.Status(); st.Abandoned != 1 {
		t.Errorf("status %+v", st)
	}
}

// Map v1 named ru = A, which the device stored; map v2 names ru = B. After
// a restart without peers, A stands in for B until B is verified.
func TestThePreviousListSurvivesARestart(t *testing.T) {
	a, refA := geoip(t, "ru", "192.0.2.0/24")
	b, refB := geoip(t, "ru", "198.51.100.0/24")
	tn := newTestNet()
	store := newMemStore()
	if err := store.Save(refA, a); err != nil {
		t.Fatal(err)
	}
	device := startNode(t, tn, 2, store, fast)
	device.Update(device.plan([]netmap.BlobRef{refB}))
	eventually(t, "A standing in", func() bool { _, ok := device.Get(refA.SHA256); return ok })
	if r, got, ok := device.Latest(netmap.BlobGeoIP, "ru"); !ok || r != refA || !bytes.Equal(got, a) {
		t.Fatalf("Latest(geoip, ru) = %v, %v; want A", r, ok)
	}
	if st := device.Status(); st.StandIns != 1 || st.Held != 0 {
		t.Errorf("status %+v", st)
	}
	time.Sleep(100 * time.Millisecond)
	if !store.has(refA) {
		t.Fatal("A pruned before B arrived")
	}

	server := startNode(t, tn, 1, newMemStore(b), fast)
	server.Update(server.plan([]netmap.BlobRef{refB}))
	device.Update(device.plan([]netmap.BlobRef{refB}, server))
	eventually(t, "B held, A gone", func() bool {
		r, _, ok := device.Latest(netmap.BlobGeoIP, "ru")
		return ok && r == refB && !store.has(refA) && store.has(refB)
	})
	// An index entry under another name stands in for nothing.
	_, refC := geoip(t, "by", "203.0.113.0/24")
	fresh := startNode(t, tn, 4, store, fast)
	fresh.Update(fresh.plan([]netmap.BlobRef{refC}))
	time.Sleep(100 * time.Millisecond)
	if st := fresh.Status(); st.StandIns != 0 {
		t.Errorf("a stand-in of another name: %+v", st)
	}
}

func TestAHeldBlobIsCheckedAgainUnderAnotherKind(t *testing.T) {
	junk := []byte("bytes that are no list")
	asOther := refOf(netmap.BlobKind(9), "", junk)
	asList := refOf(netmap.BlobGeoIP, "x", junk)
	tn := newTestNet()
	n := startNode(t, tn, 2, newMemStore(junk), fast)
	n.Update(n.plan([]netmap.BlobRef{asOther}))
	eventually(t, "held as an unknown kind", func() bool { _, ok := n.Get(asOther.SHA256); return ok })
	n.Update(n.plan([]netmap.BlobRef{asList}))
	if _, ok := n.Get(asList.SHA256); ok {
		t.Fatal("held as a GeoIP list without decoding as one")
	}

	data, ref := geoip(t, "", "192.0.2.0/24")
	list := startNode(t, tn, 3, newMemStore(data), fast)
	other := ref
	other.Kind = netmap.BlobKind(9)
	list.Update(list.plan([]netmap.BlobRef{other}))
	eventually(t, "held as an unknown kind", func() bool { _, ok := list.Get(ref.SHA256); return ok })
	list.Update(list.plan([]netmap.BlobRef{ref}))
	if _, ok := list.Get(ref.SHA256); !ok {
		t.Fatal("a good list dropped when its kind changed")
	}
}

func TestEverySubscriberHearsOfChanges(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	tn := newTestNet()
	n := startNode(t, tn, 2, newMemStore(data), fast)
	a, b := n.Subscribe(), n.Subscribe()
	n.Update(n.plan([]netmap.BlobRef{ref}))
	for _, ch := range []<-chan struct{}{a, b} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("a subscriber missed the blob arriving")
		}
	}
	n.Update(n.plan([]netmap.BlobRef{renamed(ref, "russia")}))
	for _, ch := range []<-chan struct{}{a, b} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("a subscriber missed the rename")
		}
	}
	if r, _, ok := n.Latest(netmap.BlobGeoIP, "russia"); !ok || r.Name != "russia" {
		t.Errorf("Latest under the new name: %v %v", r, ok)
	}
}

func TestADeviceServesNothing(t *testing.T) {
	data, ref := geoip(t, "ru", "192.0.2.0/24")
	tn := newTestNet()
	n := startNode(t, tn, 2, newMemStore(data), fast)
	p := n.plan([]netmap.BlobRef{ref})
	p.Listen = nil
	n.Update(p)
	eventually(t, "the list held", func() bool { _, ok := n.Get(ref.SHA256); return ok })
	tn.mu.Lock()
	defer tn.mu.Unlock()
	if len(tn.addrs) != 0 {
		t.Errorf("listening on %v", tn.addrs)
	}
}
