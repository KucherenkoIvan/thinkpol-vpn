package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// wireguardLikeSizes are the packets the path layer hands a transport:
// its 18-byte header around WireGuard's keepalive (32), cookie reply (64),
// handshake response (92) and initiation (148), and data messages (32 plus
// an inner packet padded to 16 bytes), up to a 1452-byte datagram.
func wireguardLikeSizes() []int {
	const pathHeader = 18
	sizes := []int{pathHeader + 64, pathHeader + 92, pathHeader + 148}
	for inner := 0; pathHeader+32+inner+Overhead <= 1452; inner += 16 {
		sizes = append(sizes, pathHeader+32+inner)
	}
	return sizes
}

// labBuckets is the bucket padding the measurements use: a coarse ladder
// up to the largest IPv6 datagram a 1500-byte MTU leaves.
var labBuckets = transport.Shaping{Padding: transporttest.Buckets(128, 256, 512, 1024, 1452)}

// TestPaddingHidesPacketSizes is the measurement: the same packets sent
// unshaped, padded to buckets and padded at random, as a censor's capture
// sees them in both directions.
func TestPaddingHidesPacketSizes(t *testing.T) {
	sizes := wireguardLikeSizes()
	const repeats = 4
	random := transport.Shaping{Padding: transport.Padding{Mode: transport.PadRandom, Max: 256}}
	for _, tc := range []struct {
		name    string
		shaping transport.Shaping
		check   func(t *testing.T, packet, datagram int)
		// distinct is the most distinct datagram sizes the capture may show
		distinct int
	}{
		{"none", transport.Shaping{}, func(t *testing.T, packet, datagram int) {
			if datagram != packet+Overhead {
				t.Errorf("a %d-byte packet went out as %d bytes", packet, datagram)
			}
		}, len(sizes)},
		{"buckets", labBuckets, func(t *testing.T, packet, datagram int) {
			if want := labBuckets.Padding.Size(packet + Overhead); datagram != want {
				t.Errorf("a %d-byte packet went out as %d bytes, want the %d bucket", packet, datagram, want)
			}
		}, 5},
		{"random", random, func(t *testing.T, packet, datagram int) {
			if datagram < packet+Overhead || datagram > packet+Overhead+256 {
				t.Errorf("a %d-byte packet went out as %d bytes", packet, datagram)
			}
		}, 2 * repeats * len(sizes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.peer.Shaping = tc.shaping
			f.table.Set([]transport.PeerLink{f.peer.PeerLink})
			// The listener takes table changes in the background; its
			// first reply must already be shaped.
			waitFor(t, "the shaping applied", func() bool {
				f.listener.mu.Lock()
				defer f.listener.mu.Unlock()
				fl := f.listener.flows[string(f.peer.Verifier)]
				return fl != nil && fl.entry.Load().link.Shaping.Padding == tc.shaping.Padding
			})
			client, err := f.tr.Dial(context.Background(), f.tap.addr(), transport.DialConfig{Credential: f.peer.Credential, Shaping: tc.shaping})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			up := reads(client)
			var server transport.Link
			var down <-chan []byte
			var sent []int
			for range repeats {
				for _, size := range sizes {
					p := []byte(fmt.Sprintf("%0*d", size, size))
					if err := client.WritePacket(p); err != nil {
						t.Fatal(err)
					}
					if server == nil {
						server = f.accept()
						down = reads(server)
					}
					expectPacket(t, down, p)
					if err := server.WritePacket(p); err != nil {
						t.Fatal(err)
					}
					expectPacket(t, up, p)
					sent = append(sent, size)
				}
			}

			capUp, capDown := f.tap.captured()
			if len(capUp) != len(sent) || len(capDown) != len(sent) {
				t.Fatalf("captured %d datagrams up and %d down for %d packets each way", len(capUp), len(capDown), len(sent))
			}
			seen := map[int]bool{}
			for i, size := range sent {
				tc.check(t, size, len(capUp[i]))
				tc.check(t, size, len(capDown[i]))
				seen[len(capUp[i])], seen[len(capDown[i])] = true, true
			}
			wire := make([]int, 0, len(seen))
			for n := range seen {
				wire = append(wire, n)
			}
			slices.Sort(wire)
			if len(wire) > tc.distinct {
				t.Errorf("%d distinct datagram sizes, want at most %d", len(wire), tc.distinct)
			}
			cs, ls := client.(*dialLink).Sent(), f.listener.Sent()
			t.Logf("%d distinct packet sizes went out as %d distinct datagram sizes (%d to %d bytes); overhead %.1f%% up (%d padding bytes), %.1f%% down",
				len(sizes), len(wire), wire[0], wire[len(wire)-1], 100*cs.Overhead(), cs.PaddingBytes, 100*ls.Overhead())
			if cs.Packets != uint64(len(sent)) || ls.Packets != uint64(len(sent)) {
				t.Errorf("meters counted %d and %d packets, want %d", cs.Packets, ls.Packets, len(sent))
			}
			if (tc.shaping.Padding.Mode == transport.PadNone) != (cs.PaddingBytes == 0) {
				t.Errorf("%d padding bytes sent", cs.PaddingBytes)
			}
		})
	}

	// What makes the random case hide sizes: one packet size shows as many.
	t.Run("random spreads one size", func(t *testing.T) {
		f := newFixture(t)
		client, err := f.tr.Dial(context.Background(), f.tap.addr(), transport.DialConfig{Credential: f.peer.Credential, Shaping: random})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		// In batches the tap's socket always has room for, so none is lost
		// to a reader the machine's load holds up.
		for batch := 1; batch <= 10; batch++ {
			for range 10 {
				if err := client.WritePacket(make([]byte, 166)); err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, "a batch captured", func() bool { up, _ := f.tap.captured(); return len(up) == 10*batch })
		}
		up, _ := f.tap.captured()
		seen := map[int]bool{}
		for _, d := range up {
			seen[len(d)] = true
		}
		// 100 uniform draws from 257 lengths show about 83; fewer than 50
		// happens with probability about 5e-23.
		if len(seen) < 50 {
			t.Errorf("100 packets of one size went out in only %d sizes", len(seen))
		}
	})
}

// A shaping change in the table applies to the live link's next datagram.
func TestShapingChangeAppliesToReplies(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	up := reads(client)
	write(t, client, "hello")
	server := f.accept()
	if err := server.WritePacket([]byte("plain")); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, up, []byte("plain"))
	shaped := f.peer
	shaped.Shaping = transport.Shaping{Padding: transporttest.Buckets(1000)}
	f.table.Set([]transport.PeerLink{shaped.PeerLink})
	waitFor(t, "the new shaping", func() bool {
		if err := server.WritePacket([]byte("padded")); err != nil {
			t.Fatal(err)
		}
		expectPacket(t, up, []byte("padded"))
		_, down := f.tap.captured()
		return len(down[len(down)-1]) == 1000
	})
	if _, down := f.tap.captured(); len(down[0]) != Overhead+len("plain") {
		t.Errorf("the first reply was %d bytes", len(down[0]))
	}
}

// A listener skips, and reports, peer links whose shaping udp can't honour.
func TestListenerRejectsUnsupportedShaping(t *testing.T) {
	f := newFixture(t)
	bad := transporttest.SymmetricPeer()
	bad.Shaping = transport.Shaping{CoverInterval: 1e9}
	f.table.Set([]transport.PeerLink{f.peer.PeerLink, bad.PeerLink})
	waitFor(t, "the rejection", func() bool { return len(f.listener.Rejected()) == 1 })
	if r := f.listener.Rejected()[0]; r.Peer != bad.Peer {
		t.Errorf("rejected %s, want %s", r.Peer, bad.Peer)
	}
}

// sendFrom sends d to the listener from a socket of its own, as an
// attacker on the path or a roaming dialer would, and returns the socket's
// address.
func sendFrom(t *testing.T, to net.Addr, d []byte) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if _, err := pc.WriteTo(d, to); err != nil {
		t.Fatal(err)
	}
	return pc.LocalAddr()
}

// A cover datagram ahead of any data opens no link and leaves nothing for
// the link data opens later.
func TestCoverBeforeDataOpensNoLink(t *testing.T) {
	f := newFixture(t)
	now := f.clock.now()
	for i, frames := range [][]byte{nil, make([]byte, 300)} {
		sendFrom(t, f.listener.Addr(), sealFrames(f.peer.Credential, toListener, newSenderID(now), now, uint64(i), frames))
	}
	waitFor(t, "two cover datagrams counted", func() bool { return f.listener.Counters().Cover == 2 })
	f.expectNoAccept()
	if f.camo.Calls() != 0 {
		t.Errorf("cover reached the camouflage")
	}
	client := f.dial()
	write(t, client, "data")
	server := reads(f.accept())
	expectPacket(t, server, []byte("data"))
	expectNoPacket(t, server)
	if c := f.listener.Counters(); c.Delivered != 1 || c.Cover != 2 {
		t.Errorf("counters %+v, want 1 packet delivered and 2 cover", c)
	}
}

// Cover moves a link's reply address only as data would: the current
// sender's newest counter. An older counter, a replay or an older sender
// leave it where it is.
func TestCoverMovesTheLinkOnlyAsDataWould(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	write(t, client, "hello")
	server := f.accept()
	sender, secret := client.(*dialLink).sender, f.peer.Credential
	cover := func(s senderID, counter uint64) []byte {
		return sealFrames(secret, toListener, s, f.clock.now(), counter, nil)
	}
	counted := func(field func(Counters) uint64, want uint64) func() bool {
		return func() bool { return field(f.listener.Counters()) == want }
	}

	moved := sendFrom(t, f.listener.Addr(), cover(sender, 100))
	waitFor(t, "newest cover counted", counted(func(c Counters) uint64 { return c.Cover }, 1))
	if server.RemoteAddr().String() != moved.String() {
		t.Fatalf("newest cover left the link at %v, want %v", server.RemoteAddr(), moved)
	}

	sendFrom(t, f.listener.Addr(), cover(sender, 50))
	waitFor(t, "older cover counted", counted(func(c Counters) uint64 { return c.Cover }, 2))
	sendFrom(t, f.listener.Addr(), cover(sender, 100))
	waitFor(t, "replayed cover dropped", counted(func(c Counters) uint64 { return c.Replayed }, 1))
	var older senderID
	binary.BigEndian.PutUint64(older[:8], uint64(sender.created()-int64(time.Second)))
	sendFrom(t, f.listener.Addr(), cover(older, 200))
	waitFor(t, "an older sender's cover dropped", counted(func(c Counters) uint64 { return c.StaleSender }, 1))

	if server.RemoteAddr().String() != moved.String() {
		t.Errorf("the link moved to %v on cover that isn't the newest", server.RemoteAddr())
	}
	if c := f.listener.Counters(); c.Cover != 2 || c.Delivered != 1 {
		t.Errorf("counters %+v, want 2 cover and 1 packet", c)
	}
}
