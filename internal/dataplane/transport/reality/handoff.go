package reality

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"

	xreality "github.com/xtls/reality"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// This file is the worker's side of reality behind a shared listener: the
// listener for the connections the supervisor's router handed over.

// Handoff implements transport.StreamRoutable: a worker's listener for the
// connections the supervisor's router handed over from one public
// listener, bound at address, settings being its HandoffSettings. It puts
// what REALITY learned of the target's records into this process's store,
// where REALITY's server reads them, and serves each connection as a
// standalone listener serves one that authenticated: REALITY's handshake
// on the target connection the router dialled. It checks the seal and the
// short id against its own table again, not the replay cache (the router
// admitted the hello once); what it refuses is spliced to the target.
func (t *Transport) Handoff(address string, settings []byte, admission transport.Admission) (transport.HandoffListener, error) {
	var hs handoffSettings
	if err := json.Unmarshal(settings, &hs); err != nil {
		return nil, invalid("handoff settings: %v", err)
	}
	ls, err := parseListen(hs.Listener)
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, invalid("handoff address %q: %v", address, err)
	}
	dest := ls.target.String()
	records := map[string][]int{}
	for name := range ls.names {
		for alpn := range detectedALPNs {
			key := recordsKey(dest, name, alpn)
			lens, ok := hs.Records[key]
			if !ok {
				return nil, invalid("handoff settings: no records for %q", key)
			}
			records[key] = append([]int{}, lens...)
		}
	}
	for key, lens := range records {
		xreality.GlobalPostHandshakeRecordsLens.Store(key, lens)
	}
	return newListener(t, nil, net.TCPAddrFromAddrPort(addr), ls, admission, helloCheck{t: t}), nil
}

// ServeStream implements transport.HandoffListener: the connection is
// served on a goroutine of its own.
func (l *listener) ServeStream(h transport.StreamHandoff) { go l.serveHandoff(h) }

func (l *listener) serveHandoff(h transport.StreamHandoff) {
	if h.Target == nil {
		h.Close()
		return
	}
	record := h.Consumed
	id, peer, ok := l.authenticate(record)
	if !ok {
		var tail []byte
		if len(record) >= heldBack {
			tail = record[len(record)-heldBack:]
		}
		l.gate.splice(h.Conn, h.Target, tail, h.TargetRead)
		return
	}
	if !l.gate.live.track(h.Conn, h.Target) {
		h.Close()
		return
	}
	defer l.gate.live.untrack(h.Conn, h.Target)
	ht := &handedTarget{Conn: h.Target, held: h.TargetRead, skip: len(record) - heldBack}
	l.handshake(h.Conn, record, id, peer, func(context.Context, string, string) (net.Conn, error) { return ht, nil })
}
