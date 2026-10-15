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