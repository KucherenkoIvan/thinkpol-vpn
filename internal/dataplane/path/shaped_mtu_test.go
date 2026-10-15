package path_test

import (
	"fmt"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Full-MTU WireGuard data frames on a shaped overlay TUN (not a multiple of
// 16) must count as signs of life so the follower can follow the leader, even
// when the two nodes' overlay MTUs differ.
func TestFollowerWithShapedOverlayMTU(t *testing.T) {
	for _, tc := range []struct {
		leaderMTU, followerMTU int
	}{
		{1228, 1328},
		{1276, 1228},
	} {
		t.Run(fmt.Sprintf("leader-%d-follower-%d", tc.leaderMTU, tc.followerMTU), func(t *testing.T) {
			t.Parallel()
			eachSemanticsFake(t, func(t *testing.T, f *fabric) {
				testFollowerFullMTU(t, f, tc.leaderMTU, tc.followerMTU)
			})
		})
	}
}

func testFollowerFullMTU(t *testing.T, f *fabric, leaderMTU, followerMTU int) {
	a, b := twoRelays(t, f, r1r2, []string{"R2", "R1"})
	fullA := wgFullMTUData(leaderMTU)
	fullB := wgFullMTUData(followerMTU)

	toA := b.endpoint(t, "A")
	toB := a.endpoint(t, "B")
	b.sendWG(t, toA, fullB)
	got := a.expectWG(t, fullB)
	if hop := b.current("A"); hop != "R2" {
		t.Fatalf("B starts on %q, want R2", hop)
	}
	a.sendWG(t, got.ep, fullA)
	got = b.expectWG(t, fullA)
	if hop := a.current("B"); hop != "R1" {
		t.Fatalf("A answers through %q, want R1", hop)
	}
	if b.LastSeen(id("A"), id("R1")) == 0 {
		t.Fatal("lastSeen not set for A's packets through R1")
	}
	b.sendWG(t, got.ep, fullB)
	a.expectWG(t, fullB)
	if hop := b.current("A"); hop != "R1" {
		t.Fatalf("B follows A through %q, want R1", hop)
	}
	for i := range 10 {
		f.clock.add(fakeStep)
		aHop, bHop := pingPongFullMTU(t, a, b, toB, fullA, fullB)
		if aHop != "R1" || bHop != "R1" {
			t.Fatalf("round %d: A on %q, B on %q, want both on R1", i, aHop, bHop)
		}
	}
}

func TestUnshapedOverlayMTUStillCountsFullMTU(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		const tunMTU = 1328
		a, b := twoRelays(t, f, r1r2, r1r2)
		full := wgFullMTUData(tunMTU)
		toB := a.endpoint(t, "B")
		a.sendWG(t, toB, full)
		got := b.expectWG(t, full)
		if b.LastSeen(id("A"), id("R1")) == 0 {
			t.Fatal("lastSeen not set for full-MTU frame on unshaped 1328")
		}
		b.sendWG(t, got.ep, full)
		a.expectWG(t, full)
	})
}

func TestJunkDataLengthStillRejected(t *testing.T) {
	junk := make([]byte, 50)
	junk[0] = 4
	f := newFabric(t, 0)
	a, b := twoRelays(t, f, r1r2, r1r2)
	toB := a.endpoint(t, "B")
	a.sendWG(t, toB, junk)
	b.expectWG(t, junk)
	if b.LastSeen(id("A"), id("R1")) != 0 {
		t.Fatal("junk length counted as a sign of life")
	}
}

func pingPongFullMTU(t *testing.T, a, b *rawBind, toB conn.Endpoint, fullA, fullB []byte) (aHop, bHop string) {
	t.Helper()
	a.sendWG(t, toB, fullA)
	got := b.awaitWG(t, fullA)
	b.sendWG(t, got.ep, fullB)
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
