package udp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

func TestProbesGetNoAnswer(t *testing.T) {
	f := newFixture(t)
	secret := f.peer.Credential
	now := time.Now()
	inID := connIDFor(secret, toListener, epochOf(now))
	forged := seal(nil, newAEAD(secret, toListener), inID, newSenderID(now), now, 0, []byte("hi"), transport.Padding{})
	forged[len(forged)-1] ^= 1
	other := transporttest.SymmetricPeer().Credential
	probes := map[string][]byte{
		"empty":                     {},
		"one byte":                  {1},
		"WireGuard initiation":      append([]byte{1, 0, 0, 0}, make([]byte, 144)...),
		"zeros":                     make([]byte, 1200),
		"right conn id, bad tag":    forged,
		"right conn id, wrong key":  seal(nil, newAEAD(other, toListener), inID, newSenderID(now), now, 0, []byte("hi"), transport.Padding{}),
		"other direction's conn id": seal(nil, newAEAD(secret, toDialer), connIDFor(secret, toDialer, epochOf(now)), newSenderID(now), now, 0, []byte("hi"), transport.Padding{}),
		"conn id of two hours ago":  seal(nil, newAEAD(secret, toListener), connIDFor(secret, toListener, epochOf(now)-2), newSenderID(now), now, 0, []byte("hi"), transport.Padding{}),
		"oversized":                 make([]byte, maxDatagram+1),
	}
	prober, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prober.Close() }()
	for name, p := range probes {
		before := f.camo.Calls()
		if _, err := prober.WriteTo(p, f.listener.Addr()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		waitFor(t, name+" reaching the camouflage", func() bool { return f.camo.Calls() > before })
	}
	_ = prober.SetReadDeadline(time.Now().Add(quiet))
	if n, _, err := prober.ReadFrom(make([]byte, 65536)); err == nil {
		t.Fatalf("the listener answered a probe with %d bytes", n)
	}
	f.expectNoAccept()
	if c := f.listener.Counters(); c.Unauthenticated != uint64(len(probes)) {
		t.Errorf("counted %d unauthenticated datagrams, want %d", c.Unauthenticated, len(probes))
	}
}

func TestReplaysAreDropped(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	write(t, client, "once")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("once"))
	for _, p := range []string{"two", "three"} {
		write(t, client, p)
		expectPacket(t, got, []byte(p))
	}
	before := f.camo.Calls()
	up, _ := f.tap.captured()
	for _, d := range up {
		f.tap.inject(d)
	}
	waitFor(t, "every replay at the camouflage", func() bool { return f.camo.Calls()-before >= int64(len(up)) })
	expectNoPacket(t, got)
	if f.camo.Calls()-before != int64(len(up)) {
		t.Errorf("%d replays reached the camouflage, want %d", f.camo.Calls()-before, len(up))
	}
	if c := f.listener.Counters(); c.Replayed != uint64(len(up)) {
		t.Errorf("counted %d replays, want %d", c.Replayed, len(up))
	}
}

func TestSkewedClocksAreRejected(t *testing.T) {
	for _, skew := range []time.Duration{6 * time.Minute, -6 * time.Minute} {
		t.Run(skew.String(), func(t *testing.T) {
			f := newFixture(t)
			skewed := &clock{off: skew}
			client := f.dialWith(New(Options{Now: skewed.now}))
			write(t, client, "from the future or the past")
			waitFor(t, "a stale timestamp counted", func() bool { return f.listener.Counters().StaleTimestamp > 0 })
			f.expectNoAccept()
			if f.camo.Calls() == 0 {
				t.Error("the stale datagram didn't reach the camouflage")
			}
		})
	}
	t.Run("within five minutes", func(t *testing.T) {
		f := newFixture(t)
		skewed := &clock{off: 4 * time.Minute}
		client := f.dialWith(New(Options{Now: skewed.now}))
		write(t, client, "a little ahead")
		expectPacket(t, reads(f.accept()), []byte("a little ahead"))
	})
}

func TestRestartThenReplay(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	write(t, client, "before the restart")
	expectPacket(t, reads(f.accept()), []byte("before the restart"))
	old, _ := f.tap.captured()

	f.clock.advance(6 * time.Minute)
	f.restart()
	f.tap.rebind() // the attacker's own address
	for _, d := range old {
		f.tap.inject(d)
	}
	waitFor(t, "every replay counted", func() bool { return f.listener.Counters().StaleTimestamp >= uint64(len(old)) })
	f.expectNoAccept()
	if c := f.listener.Counters(); c.StaleTimestamp != uint64(len(old)) {
		t.Fatalf("counted %d stale timestamps for %d replays", c.StaleTimestamp, len(old))
	}

	// The real dialer comes back; replays still move nothing.
	f.tap.rebind()
	write(t, client, "after the restart")
	server := f.accept()
	expectPacket(t, reads(server), []byte("after the restart"))
	addr := server.RemoteAddr().String()
	f.tap.rebind()
	for _, d := range old {
		f.tap.inject(d)
	}
	waitFor(t, "the replays counted", func() bool { return f.listener.Counters().StaleTimestamp >= 2*uint64(len(old)) })
	if got := server.RemoteAddr().String(); got != addr {
		t.Fatalf("a replay moved the link from %s to %s", addr, got)
	}
	write(t, server, "still yours")
	expectPacket(t, fromServer, []byte("still yours"))
}

func TestWithheldDatagramOlderThanTheWindow(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	write(t, client, "first")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("first"))

	f.tap.hold(true)
	write(t, client, "withheld")
	waitFor(t, "the tap holding a datagram", func() bool { f.tap.mu.Lock(); defer f.tap.mu.Unlock(); return len(f.tap.held) == 1 })
	withheld := f.tap.takeHeld()[0]
	f.tap.hold(false)

	for i := range replayWindowSize + 100 {
		_ = client.WritePacket([]byte("filler"))
		if i%64 == 0 {
			time.Sleep(time.Millisecond) // let loopback keep up
		}
	}
	waitFor(t, "the window moving past the withheld datagram", func() bool {
		_ = client.WritePacket([]byte("marker"))
		return f.listener.Counters().Delivered > replayWindowSize+50
	})
	time.Sleep(quiet) // the last markers land from the client's own address
	addr := server.RemoteAddr().String()
	replayedBefore := f.listener.Counters().Replayed
	f.tap.rebind()
	f.tap.inject(withheld)
	waitFor(t, "the withheld datagram dropped", func() bool { return f.listener.Counters().Replayed > replayedBefore })
	if a := server.RemoteAddr().String(); a != addr {
		t.Fatalf("the withheld datagram moved the link from %s to %s", addr, a)
	}
	for {
		select {
		case p := <-got:
			if string(p) == "withheld" {
				t.Fatal("the withheld datagram was delivered")
			}
			continue
		case <-time.After(quiet):
		}
		break
	}
}

// TestOldSendersCannotTakeOver cycles nine older senders' datagrams, held
// back so their counters are fresh, from an attacker's address while the
// current sender is active: none gets in, the link stays where it is.
func TestOldSendersCannotTakeOver(t *testing.T) {
	f := newFixture(t)
	f.tap.hold(true)
	for range 9 {
		old := f.dial()
		write(t, old, "an old sender")
		_ = old.Close()
	}
	waitFor(t, "the tap holding nine datagrams", func() bool { f.tap.mu.Lock(); defer f.tap.mu.Unlock(); return len(f.tap.held) == 9 })
	held := f.tap.takeHeld()
	f.tap.hold(false)

	current := f.dial()
	write(t, current, "current")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("current"))
	addr := server.RemoteAddr().String()

	f.tap.rebind()
	for range 3 {
		for _, d := range held {
			f.tap.inject(d)
		}
	}
	waitFor(t, "the old senders turned away", func() bool { return f.listener.Counters().StaleSender >= 9 })
	expectNoPacket(t, got)
	f.expectNoAccept()
	if a := server.RemoteAddr().String(); a != addr {
		t.Fatalf("an old sender moved the link from %s to %s", addr, a)
	}
}

func TestQuietSenderGivesWay(t *testing.T) {
	f := newFixture(t)
	f.tap.hold(true)
	older := f.dial() // a dialer whose clock went back would look like this
	write(t, older, "older")
	waitFor(t, "the tap holding a datagram", func() bool { f.tap.mu.Lock(); defer f.tap.mu.Unlock(); return len(f.tap.held) == 1 })
	held := f.tap.takeHeld()
	f.tap.hold(false)
	newer := f.dial()
	write(t, newer, "newer")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("newer"))

	f.tap.inject(held[0])
	expectNoPacket(t, got)
	f.clock.advance(senderTakeover + time.Second)
	write(t, older, "older again")
	expectPacket(t, got, []byte("older again"))
}

func TestReplayFromElsewhereDoesNotMoveTheLink(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	write(t, client, "one")
	write(t, client, "two")
	server := f.accept()
	fromClient := reads(server)
	expectPacket(t, fromClient, []byte("one"))
	expectPacket(t, fromClient, []byte("two"))
	before := server.RemoteAddr().String()
	up, _ := f.tap.captured()
	f.tap.rebind()
	f.tap.inject(up[0])
	expectNoPacket(t, fromClient)
	if after := server.RemoteAddr().String(); after != before {
		t.Fatalf("a replay moved the link from %s to %s", before, after)
	}
	write(t, server, "still here")
	expectPacket(t, fromServer, []byte("still here"))
}

func TestListenerFollowsARebindingDialer(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	write(t, client, "before")
	server := f.accept()
	fromClient := reads(server)
	expectPacket(t, fromClient, []byte("before"))
	before := server.RemoteAddr().String()

	f.tap.rebind()
	write(t, client, "after")
	expectPacket(t, fromClient, []byte("after"))
	if after := server.RemoteAddr().String(); after == before {
		t.Fatalf("remote address still %s after rebinding", after)
	}
	write(t, server, "found you")
	expectPacket(t, fromServer, []byte("found you"))
}

func TestConnIDsChangeAcrossTheHour(t *testing.T) {
	now := time.Now()
	boundary := now.Truncate(connIDPeriod).Add(connIDPeriod)
	f := newFixture(t)
	// The listener is just past the hour, the dialer just before it.
	f.clock.advance(boundary.Add(2 * time.Second).Sub(now))
	behind := &clock{off: boundary.Add(-2 * time.Second).Sub(now)}
	client := f.dialWith(New(Options{Now: behind.now}))
	write(t, client, "across the hour")
	server := f.accept()
	expectPacket(t, reads(server), []byte("across the hour"))
	write(t, server, "back")
	expectPacket(t, reads(client), []byte("back"))
	up, _ := f.tap.captured()
	if got, want := connID(up[0][:connIDSize]), connIDFor(f.peer.Credential, toListener, epochOf(boundary)-1); got != want {
		t.Fatalf("the dialer used conn id %x, want the previous hour's %x", got, want)
	}
}

func TestSettingsChangeKeepsTheLink(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	write(t, client, "hello")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("hello"))

	changed := f.peer.PeerLink
	changed.Settings = []byte{0x08, 0x01} // a field udp doesn't know yet: still valid
	f.table.Set([]transport.PeerLink{changed})
	waitFor(t, "the new settings applied", func() bool {
		f.listener.mu.Lock()
		defer f.listener.mu.Unlock()
		fl := f.listener.flows[string(changed.Verifier)]
		return fl != nil && bytes.Equal(fl.entry.Load().link.Settings, changed.Settings)
	})
	write(t, client, "same link")
	expectPacket(t, got, []byte("same link"))

	renamed := changed
	renamed.Peer = transporttest.RandomIdentity()
	f.table.Set([]transport.PeerLink{renamed})
	waitFor(t, "the link revoked", func() bool {
		return errors.Is(server.WritePacket([]byte("x")), transport.ErrRevoked)
	})
}

func TestUnusablePeerLinksAreReported(t *testing.T) {
	good, dupA := transporttest.SymmetricPeer(), transporttest.SymmetricPeer()
	dupB := dupA
	dupB.Peer = transporttest.RandomIdentity()
	short := transport.PeerLink{Peer: transporttest.RandomIdentity(), Verifier: make([]byte, MinSecretSize-1)}
	badSettings := transporttest.SymmetricPeer().PeerLink
	badSettings.Settings = []byte{0xff}
	table := transport.NewPeerTable(good.PeerLink, dupA.PeerLink, dupB.PeerLink, short, badSettings)
	tr := New(Options{})
	l := tr.ListenOn(mustListenPacket(t), transport.ListenConfig{Peers: table})
	defer func() { _ = l.Close() }()
	rejected := map[transport.Identity]bool{}
	for _, pe := range l.Rejected() {
		rejected[pe.Peer] = true
	}
	for name, id := range map[string]transport.Identity{
		"duplicate secret": dupA.Peer, "its twin": dupB.Peer, "short verifier": short.Peer, "bad settings": badSettings.Peer,
	} {
		if !rejected[id] {
			t.Errorf("%s not reported", name)
		}
	}
	if rejected[good.Peer] || len(rejected) != 4 {
		t.Errorf("rejected %v", l.Rejected())
	}
	if err := tr.CheckInbound(short); err == nil {
		t.Error("CheckInbound passed a short verifier")
	}
	if err := tr.CheckEndpoint("example.org:443", transport.DialConfig{Credential: good.Credential}); err == nil {
		t.Error("CheckEndpoint passed a host name")
	}
}

func mustListenPacket(t *testing.T) net.PacketConn {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestWireCarriesNoPlaintext(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	marker := []byte("PLAINTEXT-MARKER-0123456789")
	if err := client.WritePacket(marker); err != nil {
		t.Fatal(err)
	}
	server := f.accept()
	if err := server.WritePacket(marker); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, reads(client), marker)
	up, down := f.tap.captured()
	for _, d := range append(up, down...) {
		if bytes.Contains(d, marker[:10]) {
			t.Fatalf("plaintext on the wire: %x", d)
		}
	}
}

// TestNoncesNeverRepeat checks the wire across everything that resets a
// sender: a redial, a listener restart, a server-side close.
func TestNoncesNeverRepeat(t *testing.T) {
	f := newFixture(t)
	exchange := func(client transport.Link) {
		t.Helper()
		write(t, client, "ping")
		server := f.accept()
		expectPacket(t, reads(server), []byte("ping"))
		for i := range 10 {
			write(t, server, fmt.Sprint("pong ", i))
		}
		_ = server.Close()
	}
	exchange(f.dial())
	exchange(f.dial())
	f.restart()
	exchange(f.dial())
	time.Sleep(quiet)
	up, down := f.tap.captured()
	seen := map[string]bool{}
	for _, d := range append(up, down...) {
		n := string(d[connIDSize:clearSize])
		if seen[n] {
			t.Fatalf("nonce %x used twice", n)
		}
		seen[n] = true
	}
	if len(seen) < 30 {
		t.Fatalf("only %d datagrams captured", len(seen))
	}
}

// TestNineRedialsThenQuietThenOldest replays every redial's first datagram
// once the current sender has gone quiet: the oldest was evicted from the
// slots, the others are remembered, and none gets back in. The dialers'
// clocks are ahead by the allowed skew, so the evicted oldest's datagram
// is still fresh a full skew past its eviction on the listener's clock —
// it is refused only while the evicted are remembered for twice the skew.
func TestNineRedialsThenQuietThenOldest(t *testing.T) {
	f := newFixture(t)
	// Nodes' clocks may be off by maxClockSkew; the worst case for the
	// replay memory is a sender at the full skew ahead.
	skewed := New(Options{Now: (&clock{off: maxClockSkew}).now})
	var server transport.Link
	var got <-chan []byte
	for i := range 9 {
		d := f.dialWith(skewed)
		p := fmt.Sprint("dial ", i)
		write(t, d, p)
		if i == 0 {
			server = f.accept()
			got = reads(server)
		}
		expectPacket(t, got, []byte(p))
	}
	up, _ := f.tap.captured()
	addr := server.RemoteAddr().String()

	// Past one skew the oldest would be forgotten if the memory ran on
	// the receiver's clock alone; its datagram is fresh until two.
	f.clock.advance(senderTakeover + maxClockSkew + 15*time.Second)
	f.tap.rebind()
	before := f.listener.Counters()
	for _, d := range up {
		f.tap.inject(d)
	}
	waitFor(t, "every replay turned away", func() bool {
		c := f.listener.Counters()
		return c.StaleSender+c.Replayed-before.StaleSender-before.Replayed == uint64(len(up))
	})
	if c := f.listener.Counters(); c.StaleSender == before.StaleSender {
		t.Error("the evicted oldest sender wasn't refused as stale")
	}
	expectNoPacket(t, got)
	f.expectNoAccept()
	if a := server.RemoteAddr().String(); a != addr {
		t.Fatalf("a replay moved the link from %s to %s", addr, a)
	}
}

// TestRefusedSenderStaysRefused shows a held datagram of an older sender
// while the current one is active, then again once it has gone quiet: the
// second time it is a replay.
func TestRefusedSenderStaysRefused(t *testing.T) {
	f := newFixture(t)
	f.tap.hold(true)
	older := f.dial()
	write(t, older, "older")
	waitFor(t, "the tap holding a datagram", func() bool { f.tap.mu.Lock(); defer f.tap.mu.Unlock(); return len(f.tap.held) == 1 })
	held := f.tap.takeHeld()[0]
	f.tap.hold(false)
	newer := f.dial()
	write(t, newer, "newer")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("newer"))
	addr := server.RemoteAddr().String()

	f.tap.rebind()
	f.tap.inject(held)
	waitFor(t, "the older sender refused", func() bool { return f.listener.Counters().StaleSender == 1 })
	f.clock.advance(senderTakeover + time.Second)
	f.tap.inject(held)
	waitFor(t, "the held datagram treated as a replay", func() bool { return f.listener.Counters().Replayed == 1 })
	expectNoPacket(t, got)
	f.expectNoAccept()
	if a := server.RemoteAddr().String(); a != addr {
		t.Fatalf("the held datagram moved the link from %s to %s", addr, a)
	}
}

// TestAClosedLinkReopensWhileTheDialerKeepsSending: the exit closes a
// link by mistake while the dialer is alive (its probes lost behind bulk
// traffic, data still arriving): the dialer's next datagram — same sender,
// same port, newest counter — reopens a link at once.
func TestAClosedLinkReopensWhileTheDialerKeepsSending(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromClient := reads(client)
	write(t, client, "before")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("before"))

	_ = server.Close() // the exit gave up on the remote by mistake

	write(t, client, "after")
	reopened := f.accept()
	expectPacket(t, reads(reopened), []byte("after"))
	write(t, reopened, "still yours")
	expectPacket(t, fromClient, []byte("still yours"))
}

// TestAClosedLinkReopensOnANewPort: the same sender from a new port opens
// a link too; nothing about the close locks a rebinding dialer out.
func TestAClosedLinkReopensOnANewPort(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromClient := reads(client)
	write(t, client, "before")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("before"))

	_ = server.Close()
	f.tap.rebind()
	write(t, client, "after")
	reopened := f.accept()
	expectPacket(t, reads(reopened), []byte("after"))
	write(t, reopened, "still yours")
	expectPacket(t, fromClient, []byte("still yours"))
}

// TestAReorderedDatagramOpensNoLinkAfterTheClose: a datagram older than
// the newest seen, from the port the app closed the link on, opens no link
// toward it; the dialer's next newest one does.
func TestAReorderedDatagramOpensNoLinkAfterTheClose(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	write(t, client, "one")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("one"))

	f.tap.hold(true)
	write(t, client, "in flight")
	waitFor(t, "the tap holding a datagram", func() bool { f.tap.mu.Lock(); defer f.tap.mu.Unlock(); return len(f.tap.held) == 1 })
	held := f.tap.takeHeld()[0]
	f.tap.hold(false)
	write(t, client, "newer")
	expectPacket(t, got, []byte("newer"))

	_ = server.Close()
	before := f.camo.Calls()
	f.tap.inject(held) // older than the newest seen, from the closed port
	waitFor(t, "the reordered datagram at the camouflage", func() bool { return f.camo.Calls() > before })
	f.expectNoAccept()

	write(t, client, "after")
	expectPacket(t, reads(f.accept()), []byte("after"))
}

// TestALateDatagramFromTheDeadPortDoesNotReopen: the app closed the link
// because its remote stopped answering; a reordered datagram that port had
// already sent arrives late and opens no new link toward it. A dialer that
// comes back redials — a new sender, from a new port — and still opens one.
func TestALateDatagramFromTheDeadPortDoesNotReopen(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	write(t, client, "first")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("first"))

	f.tap.hold(true)
	write(t, client, "in flight")
	waitFor(t, "the tap holding a datagram", func() bool { f.tap.mu.Lock(); defer f.tap.mu.Unlock(); return len(f.tap.held) == 1 })
	held := f.tap.takeHeld()[0]
	f.tap.hold(false)
	write(t, client, "newer") // moves the window past the held datagram
	expectPacket(t, got, []byte("newer"))

	_ = client.Close() // the dialer's port dies
	_ = server.Close() // the listener's link is closed on it

	before := f.camo.Calls()
	f.tap.inject(held) // late and older than the newest seen, from the dead port
	waitFor(t, "the late datagram at the camouflage", func() bool { return f.camo.Calls() > before })
	f.expectNoAccept()

	f.tap.rebind()
	fresh := f.dial()
	write(t, fresh, "fresh")
	expectPacket(t, reads(f.accept()), []byte("fresh"))
}

// TestAnEvictedSenderThatKeepsSendingStaysRemembered: a sender evicted
// from the slots that keeps sending — its datagrams turned away — must
// stay remembered as long as its newest datagrams are fresh. Measured from
// the eviction alone, the memory runs out while a tap's capture of its
// latest datagrams is still replayable. The sender's clock is ahead by the
// full allowed skew.
func TestAnEvictedSenderThatKeepsSendingStaysRemembered(t *testing.T) {
	f := newFixture(t)
	// The sender's clock is ahead by the full allowed skew, and moves
	// with the fixture's, so its sealed send times advance as the
	// listener's clock is moved forward.
	skewed := New(Options{Now: func() time.Time { return f.clock.now().Add(maxClockSkew) }})
	first := f.dialWith(skewed)
	write(t, first, "first")
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("first"))
	for i := range maxSenders { // nine senders: the first is evicted
		d := f.dialWith(skewed)
		p := fmt.Sprint("dial ", i)
		write(t, d, p)
		expectPacket(t, got, []byte(p))
	}

	// The evicted sender keeps sending, thirty seconds after the eviction.
	f.clock.advance(30 * time.Second)
	f.tap.hold(true)
	write(t, first, "still sending")
	waitFor(t, "the tap holding a datagram", func() bool { f.tap.mu.Lock(); defer f.tap.mu.Unlock(); return len(f.tap.held) == 1 })
	held := f.tap.takeHeld()[0]
	f.tap.hold(false)
	f.tap.inject(held) // the tap took it off the wire; the listener turns it away
	waitFor(t, "the turned-away datagram counted", func() bool { return f.listener.Counters().StaleSender > 0 })

	// Forgotten ten minutes after the eviction, the id comes back while
	// the captured datagram — sealed thirty seconds later on a clock a
	// skew ahead — is fresh for another skew yet.
	f.clock.advance(2*maxClockSkew - 15*time.Second)
	f.tap.rebind()
	addr := server.RemoteAddr().String()
	before := f.listener.Counters()
	f.tap.inject(held)
	waitFor(t, "the replay turned away", func() bool {
		c := f.listener.Counters()
		return c.StaleSender+c.Replayed > before.StaleSender+before.Replayed
	})
	f.expectNoAccept()
	expectNoPacket(t, got)
	if a := server.RemoteAddr().String(); a != addr {
		t.Fatalf("the replay moved the link from %s to %s", addr, a)
	}
}

// TestRemovedSecretKeepsItsHistory takes a credential out of the table and
// puts it back: what was captured before is still a replay.
func TestRemovedSecretKeepsItsHistory(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	write(t, client, "hello")
	server := f.accept()
	expectPacket(t, reads(server), []byte("hello"))
	up, _ := f.tap.captured()

	f.table.Set(nil)
	waitFor(t, "the link revoked", func() bool { return errors.Is(server.WritePacket([]byte("x")), transport.ErrRevoked) })
	f.table.Set([]transport.PeerLink{f.peer.PeerLink})
	waitFor(t, "the credential back", func() bool {
		f.listener.mu.Lock()
		defer f.listener.mu.Unlock()
		return f.listener.flows[string(f.peer.Verifier)] != nil
	})
	f.tap.rebind()
	for _, d := range up {
		f.tap.inject(d)
	}
	waitFor(t, "the replays recognised", func() bool { return f.listener.Counters().Replayed == uint64(len(up)) })
	f.expectNoAccept()

	write(t, client, "fresh")
	expectPacket(t, reads(f.accept()), []byte("fresh"))
}
