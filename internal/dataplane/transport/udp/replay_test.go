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

// TestAnEvictedSenderIsRememberedForTwoSkews: a datagram sealed as the
// sender was evicted, by a sender clocked ahead by the allowed skew, is
// still fresh one skew later on the receiver's clock, so the id must be
// refused for two.
func TestAnEvictedSenderIsRememberedForTwoSkews(t *testing.T) {
	var e evictedSenders
	id := senderID{}
	now := time.Now()
	e.add(id, now)
	if !e.has(id, now.Add(maxClockSkew+time.Second)) {
		t.Fatal("the evicted sender was forgotten after one skew, while a datagram sealed as it was evicted is still fresh for two")
	}
	if e.has(id, now.Add(2*maxClockSkew+time.Second)) {
		t.Fatal("the evicted sender is remembered past two skews")
	}
}

// TestAReplayDoesNotRefreshTheLRUStamp: a sender whose only traffic is
// replays stays the oldest slot and is evicted — and remembered — first,
// instead of holding a slot while an active sender is evicted around it.
func TestAReplayDoesNotRefreshTheLRUStamp(t *testing.T) {
	var s senders
	now := time.Now()
	for i := int64(1); i <= maxSenders; i++ {
		if v := s.admit(senderIDFor(i), 0, now); v != deliverNewest {
			t.Fatalf("sender %d's verdict is %v", i, v)
		}
	}
	oldest := senderIDFor(1)
	if v := s.admit(oldest, 0, now); v != dropReplay {
		t.Fatalf("the oldest sender's replay: %v", v)
	}
	// The replay must not make the oldest sender's slot look recently
	// used: the next sender evicts it, not the active one behind it.
	if v := s.admit(senderIDFor(maxSenders+1), 0, now); v != deliverNewest {
		t.Fatalf("the newest sender's verdict is %v", v)
	}
	if v := s.admit(oldest, 0, now); v != dropStale {
		t.Fatalf("the oldest sender's verdict after the eviction is %v, want %v", v, dropStale)
	}
}
