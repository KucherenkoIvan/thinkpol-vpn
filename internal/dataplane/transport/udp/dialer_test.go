package udp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// The dialer runs the ladder's checked half over what it reads; these
// tests replay and forge at it the way the listener-side tests replay at
// the listener.

// TestDialerDropsAReplayedDatagram: a datagram the listener sent, captured
// and shown to the dialer again, is a replay.
func TestDialerDropsAReplayedDatagram(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	write(t, client, "hello")
	waitFor(t, "the first datagram reaching the listener", func() bool { return f.listener.Counters().Delivered > 0 })
	server := f.accept()
	expectPacket(t, reads(server), []byte("hello"))
	write(t, server, "once")
	expectPacket(t, fromServer, []byte("once"))
	_, down := f.tap.captured()
	f.tap.injectDown(down[0])
	expectNoPacket(t, fromServer)
	if c := client.(*dialLink).Counters(); c.Replayed != 1 {
		t.Fatalf("counted %d replays, want 1", c.Replayed)
	}
}

// TestDialerDropsAStaleTimestamp: a datagram from the listener's direction
// sealed six minutes ago is dropped for its timestamp.
func TestDialerDropsAStaleTimestamp(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	write(t, client, "hello")
	waitFor(t, "the first datagram reaching the listener", func() bool { return f.listener.Counters().Delivered > 0 })
	_ = f.accept()
	now := f.clock.now()
	d := seal(nil, newAEAD(f.peer.Credential, toDialer), connIDFor(f.peer.Credential, toDialer, epochOf(now)), newSenderID(now), now.Add(-6*time.Minute), 0, []byte("late"), transport.Padding{})
	f.tap.injectDown(d)
	expectNoPacket(t, fromServer)
	if c := client.(*dialLink).Counters(); c.StaleTimestamp != 1 {
		t.Fatalf("counted %d stale timestamps, want 1", c.StaleTimestamp)
	}
}

// TestDialerDropsAnOlderSender: a datagram of a sender older than the
// listener's current one — what a listener that restarted late would send —
// is turned away as a stale sender.
func TestDialerDropsAnOlderSender(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	write(t, client, "hello")
	waitFor(t, "the first datagram reaching the listener", func() bool { return f.listener.Counters().Delivered > 0 })
	server := f.accept()
	write(t, server, "once")
	expectPacket(t, fromServer, []byte("once"))
	_, down := f.tap.captured()
	current, err := open(nil, newAEAD(f.peer.Credential, toDialer), down[0])
	if err != nil {
		t.Fatal(err)
	}
	older := current.sender
	binary.BigEndian.PutUint64(older[:8], uint64(current.sender.created()-int64(time.Hour)))
	now := f.clock.now()
	d := seal(nil, newAEAD(f.peer.Credential, toDialer), connIDFor(f.peer.Credential, toDialer, epochOf(now)), older, now, 0, []byte("older"), transport.Padding{})
	f.tap.injectDown(d)
	expectNoPacket(t, fromServer)
	if c := client.(*dialLink).Counters(); c.StaleSender != 1 {
		t.Fatalf("counted %d stale senders, want 1", c.StaleSender)
	}
}
