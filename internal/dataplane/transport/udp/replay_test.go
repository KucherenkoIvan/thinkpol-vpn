package udp

import (
	"encoding/binary"
	"testing"
	"time"
)

// senderIDFor builds a sender id created at the given Unix nanoseconds, so
// tests can order senders by creation time.
func senderIDFor(created int64) senderID {
	var s senderID
	binary.BigEndian.PutUint64(s[:8], uint64(created))
	return s
}

// TestAnEvictedSenderKeepsRefreshingItsMemory: a sender evicted from the
// slots that keeps sending — its datagrams turned away — must stay
// remembered as long as its newest datagrams are fresh, not from the
// eviction alone: measured from the eviction, the memory runs out while a
// tap's capture of its latest datagrams is still replayable.
func TestAnEvictedSenderKeepsRefreshingItsMemory(t *testing.T) {
	var s senders
	base := time.Unix(1_800_000_000, 0)
	sent := uint32(base.Unix())
	if v := s.admit(senderIDFor(1), 0, sent, base); v != deliverNewest {
		t.Fatalf("the first sender's verdict is %v", v)
	}
	for i := int64(2); i <= maxSenders+1; i++ { // the first sender evicted
		if v := s.admit(senderIDFor(i), 0, sent, base); v != deliverNewest {
			t.Fatalf("sender %d's verdict is %v", i, v)
		}
	}
	// Thirty seconds later it is still sending; its clock, a skew ahead,
	// seals its newest datagram thirty seconds plus a skew past the
	// eviction.
	at30 := base.Add(30 * time.Second)
	sealed := uint32(at30.Add(maxClockSkew).Unix())
	if v := s.admit(senderIDFor(1), 1, sealed, at30); v != dropStale {
		t.Fatalf("the evicted sender's verdict is %v, want %v", v, dropStale)
	}
	// Measured from the eviction alone, the memory would forget the id
	// ten minutes after it; its newest datagram is fresh until thirty
	// seconds plus two skews.
	replayAt := base.Add(2*maxClockSkew + 15*time.Second)
	if v := s.admit(senderIDFor(maxSenders+2), 0, uint32(replayAt.Unix()), replayAt); v != deliverNewest {
		t.Fatalf("the newcomer's verdict is %v", v)
	}
	if v := s.admit(senderIDFor(1), 2, sealed, replayAt); v != dropStale {
		t.Fatalf("the evicted sender's verdict is %v, want %v", v, dropStale)
	}
	if senderInSlot(&s, senderIDFor(1)) {
		t.Fatal("the evicted sender's memory ran out while its newest datagrams are still fresh")
	}
}

// TestTheMemoryExpiresExactlyWhenFreshnessDoes: freshness reads whole
// seconds, so the newest datagram a sender could have sealed as it was
// evicted (its clock a skew ahead, truncated to the second) stays fresh a
// little past two skews; the memory must not run out sooner on finer ones.
func TestTheMemoryExpiresExactlyWhenFreshnessDoes(t *testing.T) {
	var s senders
	at := time.Unix(1_800_000_000, 500_000_000)
	sealed := uint32(at.Add(maxClockSkew).Unix())
	id := senderIDFor(1)
	if v := s.admit(id, 0, sealed, at); v != deliverNewest {
		t.Fatalf("the first sender's verdict is %v", v)
	}
	for i := int64(2); i <= maxSenders+1; i++ {
		if v := s.admit(senderIDFor(i), 0, sealed, at); v != deliverNewest {
			t.Fatalf("sender %d's verdict is %v", i, v)
		}
	}
	t1 := at.Add(2*maxClockSkew + 300*time.Millisecond)
	if v := s.admit(id, 1, sealed, t1); v != dropStale {
		t.Fatal("forgotten while a datagram sealed as it was evicted is still fresh")
	}
	if senderInSlot(&s, id) {
		t.Fatal("forgotten while a datagram sealed as it was evicted is still fresh")
	}
	t2 := at.Add(2*maxClockSkew + 1200*time.Millisecond)
	if v := s.admit(senderIDFor(maxSenders+2), 0, uint32(t2.Unix()), t2); v != deliverNewest {
		t.Fatalf("the newcomer's verdict is %v", v)
	}
	if v := s.admit(id, 2, sealed, t2); v != dropStale {
		t.Fatalf("the evicted sender's verdict is %v, want %v", v, dropStale)
	}
	if !senderInSlot(&s, id) {
		t.Fatal("remembered past what the freshness check accepts")
	}
}

func senderInSlot(s *senders, id senderID) bool {
	for i := range s.entries {
		c := &s.entries[i]
		if c.used != 0 && c.id == id {
			return true
		}
	}
	return false
}

// TestAReplayDoesNotRefreshTheLRUStamp: a sender whose only traffic is
// replays stays the oldest slot and is evicted — and remembered — first,
// instead of holding a slot while an active sender is evicted around it.
func TestAReplayDoesNotRefreshTheLRUStamp(t *testing.T) {
	var s senders
	now := time.Now()
	sent := uint32(now.Unix())
	for i := int64(1); i <= maxSenders; i++ {
		if v := s.admit(senderIDFor(i), 0, sent, now); v != deliverNewest {
			t.Fatalf("sender %d's verdict is %v", i, v)
		}
	}
	oldest := senderIDFor(1)
	if v := s.admit(oldest, 0, sent, now); v != dropReplay {
		t.Fatalf("the oldest sender's replay: %v", v)
	}
	// The replay must not make the oldest sender's slot look recently
	// used: the next sender evicts it, not the active one behind it.
	if v := s.admit(senderIDFor(maxSenders+1), 0, sent, now); v != deliverNewest {
		t.Fatalf("the newest sender's verdict is %v", v)
	}
	if v := s.admit(oldest, 0, sent, now); v != dropStale {
		t.Fatalf("the oldest sender's verdict after the eviction is %v, want %v", v, dropStale)
	}
}
