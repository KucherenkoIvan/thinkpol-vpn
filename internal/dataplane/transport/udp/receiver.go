package udp

import (
	"crypto/cipher"
	"time"
)

// admitLadder is the authenticate-and-admit ladder the package doc describes
// under "What a receiver accepts", shared by the listener, the router and
// the dialer: the open, the freshness check, the sender rules, and the
// counters for everything turned away. The caller does the steps where
// the ends differ — holding the lock, delivering the packets to the link —
// and calls the ladder under its own lock.
type admitLadder struct {
	counters counters
}

// admit runs the ladder over a datagram of a table receiver (a Listener
// or a Router): it takes the datagram's connection id, finds the
// credential in set, which the caller keeps current, opens the datagram
// into dst, and puts it to the sender rules of the secret's history in
// table. It reports the entry the datagram authenticated under, the
// opened datagram, and how far it got.
func (r *admitLadder) admit(dst []byte, set *peerSet, table *senderHistories, d []byte, now time.Time) (*peerEntry, opened, verdict) {
	id, ok := idOf(d)
	if !ok {
		r.counters.unauthenticated.Add(1)
		return nil, opened{}, dropUnauthenticated
	}
	e := set.lookup(id, epochOf(now))
	if e == nil {
		r.counters.unauthenticated.Add(1)
		return nil, opened{}, dropUnauthenticated
	}
	o, v := r.admitOne(dst, table.historyOf(e.link.Verifier), e.recv, d, now)
	return e, o, v
}

// admitOne is admit for a receiver of one credential, the dialer's: it
// opens the datagram into dst under recv and puts it to the sender rules
// of s. It counts what it turns away; the packets delivered are the
// caller's to count, when it has delivered them.
func (r *admitLadder) admitOne(dst []byte, s *senders, recv cipher.AEAD, d []byte, now time.Time) (opened, verdict) {
	o, err := open(dst, recv, d)
	switch {
	case err != nil:
		r.counters.unauthenticated.Add(1)
		return opened{}, dropUnauthenticated
	case !o.fresh(now):
		r.counters.staleTimestamp.Add(1)
		return opened{}, dropStaleTimestamp
	}
	v := s.admit(o.sender, o.counter, o.sent, now)
	switch v {
	case dropReplay:
		r.counters.replayed.Add(1)
		return opened{}, dropReplay
	case dropStale:
		r.counters.staleSender.Add(1)
		return opened{}, dropStale
	}
	return o, v
}

// senderHistories is a receiver's memory of the senders of every secret in
// its peer table. A secret's history outlives its stay in the table for
// as long as one of its datagrams could still be fresh, so taking a
// secret out of the table and putting it back doesn't reopen it to
// replays. The listener and the router own one each, and serialize it
// under their own lock.
type senderHistories struct {
	histories map[string]*senders // by secret
	retired   map[string]*senders // senders of secrets gone from the table
}

func newSenderHistories() *senderHistories {
	return &senderHistories{histories: make(map[string]*senders), retired: make(map[string]*senders)}
}

// historyOf returns the secret's sender history: the one it has, a retired
// one the last table change left, or a new one. The secret is the
// verifier's slice: the hot path looks the history up for every datagram,
// and the map index of string(secret) doesn't allocate, a string
// conversion of the whole secret would.
func (t *senderHistories) historyOf(secret []byte) *senders {
	if s, ok := t.histories[string(secret)]; ok {
		return s
	}
	s, ok := t.retired[string(secret)]
	if !ok {
		s = &senders{}
	} else {
		delete(t.retired, string(secret))
	}
	t.histories[string(secret)] = s
	return s
}

// follow re-ties the histories to a peer table just indexed: a secret that
// stays keeps its history, one that left has it retired while its
// datagrams could still be fresh, and retired ones past that are
// forgotten.
func (t *senderHistories) follow(set *peerSet, now time.Time) {
	for key, s := range t.retired {
		if !sentFresh(s.newest, now) {
			delete(t.retired, key)
		}
	}
	for key, s := range t.histories {
		if set.bySecret[key] == nil {
			t.retired[key] = s
			delete(t.histories, key)
		}
	}
	for key := range set.bySecret {
		t.historyOf([]byte(key))
	}
}
