package udp

import (
	"crypto/cipher"
	"time"
)

// admitLadder is the authenticate-and-admit ladder the package doc describes
// under "What a receiver accepts", and the counters for everything it turns
// away. admit runs it whole for a table receiver (the listener, the router):
// the connection id, the lookup, the open, the freshness check, the sender
// rules. admitOne runs it from the open on, for the dialer, which checks its
// own connection id. The caller holds its lock across the call and delivers
// the packets itself.
type admitLadder struct {
	counters counters
}

// admit runs the ladder over a datagram of a table receiver (a Listener
// or a Router): it takes the datagram's connection id, finds the
// credential in set, which the caller keeps current, opens the datagram
// into dst, and puts it to the sender rules of the secret's history in
// table. It reports the entry the datagram authenticated under, the
// opened datagram, and how far it got.
func (a *admitLadder) admit(dst []byte, set *peerSet, table *senderHistories, d []byte, now time.Time) (*peerEntry, opened, verdict) {
	id, ok := idOf(d)
	if !ok {
		a.counters.unauthenticated.Add(1)
		return nil, opened{}, dropUnauthenticated
	}
	e := set.lookup(id, epochOf(now))
	if e == nil {
		a.counters.unauthenticated.Add(1)
		return nil, opened{}, dropUnauthenticated
	}
	o, v := a.admitOne(dst, table.historyOf(e.link.Verifier), e.recv, d, now)
	return e, o, v
}

// admitOne is admit for a receiver of one credential, the dialer's: it
// opens the datagram into dst under recv and puts it to the sender rules
// of s. It counts what it turns away; the packets delivered are the
// caller's to count, when it has delivered them.
func (a *admitLadder) admitOne(dst []byte, s *senders, recv cipher.AEAD, d []byte, now time.Time) (opened, verdict) {
	o, err := open(dst, recv, d)
	switch {
	case err != nil:
		a.counters.unauthenticated.Add(1)
		return opened{}, dropUnauthenticated
	case !o.fresh(now):
		a.counters.staleTimestamp.Add(1)
		return opened{}, dropStaleTimestamp
	}
	v := s.admit(o.sender, o.counter, o.sent, now)
	switch v {
	case dropReplay:
		a.counters.replayed.Add(1)
		return opened{}, dropReplay
	case dropStale:
		a.counters.staleSender.Add(1)
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
// one the last table change left, or a new one. The lookup m[string(secret)]
// doesn't copy secret; only inserting a new history does.
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
