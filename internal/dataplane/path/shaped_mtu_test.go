package path_test

import (
	"fmt"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Full-MTU WireGuard data frames on a shaped overlay TUN (not a multiple of
// 16) must count as signs of life so the follower can follow the leader.
func TestFollowerWithShapedOverlayMTU(t *testing.T) {
	for _, mtu := range []int{1228, 1276} {
		t.Run(fmt.Sprintf("mtu-%d", mtu), func(t *testing.T) {
			t.Parallel()
			eachSemanticsFake(t, func(t *testing.T, f *fabric) {
				testFollowerFullMTU(t, f, mtu)
			})
		})
	}
}

func testFollowerFullMTU(t *testing.T, f *fabric, tunMTU int) {
	a, b := twoRelays(t, f, r1r2, []string{"R2", "R1"})
	a.Bind.SetWireGuardMTU(tunMTU)
	b.Bind.SetWireGuardMTU(tunMTU)
	full := wgFullMTUData(tunMTU)

	toA := b.endpoint(t, "A")
	toB := a.endpoint(t, "B")
	b.sendWG(t, toA, full)
	got := a.expectWG(t, full)
	if hop := b.current("A"); hop != "R2" {
		t.Fatalf("B starts on %q, want R2", hop)
	}
	a.sendWG(t, got.ep, full)
	got = b.expectWG(t, full)
	if hop := a.current("B"); hop != "R1" {
		t.Fatalf("A answers through %q, want R1", hop)
	}
	if b.Bind.LastSeen(id("A"), id("R1")) == 0 {
		t.Fatal("lastSeen not set for A's packets through R1")
	}
	b.sendWG(t, got.ep, full)
	a.expectWG(t, full)
	if hop := b.current("A"); hop != "R1" {
		t.Fatalf("B follows A through %q, want R1", hop)
	}
	for i := range 10 {
		f.clock.add(fakeStep)
		aHop, bHop := pingPongFullMTU(t, a, b, toB, full)
		if aHop != "R1" || bHop != "R1" {
			t.Fatalf("round %d: A on %q, B on %q, want both on R1", i, aHop, bHop)
		}
	}
}

func TestUnshapedOverlayMTUStillCountsFullMTU(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		const tunMTU = 1328
		a, b := twoRelays(t, f, r1r2, r1r2)
		a.Bind.SetWireGuardMTU(tunMTU)
		b.Bind.SetWireGuardMTU(tunMTU)
		full := wgFullMTUData(tunMTU)
		toB := a.endpoint(t, "B")
		a.sendWG(t, toB, full)
		got := b.expectWG(t, full)
		if b.Bind.LastSeen(id("A"), id("R1")) == 0 {
			t.Fatal("lastSeen not set for full-MTU frame on unshaped 1328")
		}
		b.sendWG(t, got.ep, full)
		a.expectWG(t, full)
	})
}

func TestJunkDataLengthStillRejected(t *testing.T) {
	const tunMTU = 1228
	junk := make([]byte, 50)
	junk[0] = 4
	f := newFabric(t, 0)
	a, b := twoRelays(t, f, r1r2, r1r2)
	b.Bind.SetWireGuardMTU(tunMTU)
	toB := a.endpoint(t, "B")
	a.sendWG(t, toB, junk)
	b.expectWG(t, junk)
	if b.Bind.LastSeen(id("A"), id("R1")) != 0 {
		t.Fatal("junk length counted as a sign of life")
	}
}

func pingPongFullMTU(t *testing.T, a, b *rawBind, toB conn.Endpoint, msg []byte) (aHop, bHop string) {
	t.Helper()
	a.sendWG(t, toB, msg)
	got := b.awaitWG(t, msg)
	b.sendWG(t, got.ep, wgMsg("ack"))
	a.drain()
	return a.current("B"), b.current("A")
}

func (b *rawBind) expectWG(t *testing.T, want []byte) received {
	t.Helper()
	select {
	case r := <-b.got:
		if len(r.msg) != len(want) {
			t.Fatalf("got %d bytes, want %d", len(r.msg), len(want))
		}
		return r
	case <-time.After(wait):
		t.Fatalf("message of %d bytes never arrived", len(want))
	}
	return received{}
}

func (b *rawBind) awaitWG(t *testing.T, want []byte) received {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case r := <-b.got:
			if len(r.msg) == len(want) {
				return r
			}
		case <-deadline:
			t.Fatalf("message of %d bytes never arrived", len(want))
		}
	}
}
