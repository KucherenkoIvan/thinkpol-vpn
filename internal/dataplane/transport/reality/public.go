package reality

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// This file is the supervisor's side of reality behind a shared listener:
// the public listener, which decides each connection with its router
// (router.go) and splices what it turns away to the target.

var _ transport.StreamRoutable = (*Transport)(nil)

// ListenStream implements transport.StreamRoutable: the public listener a
// server node's supervisor accepts on, routing with sr, a router of this
// transport. It checks the target as Listen does (its certificate, then
// REALITY's detection of its post-handshake records) and keeps what
// REALITY learned for the workers' handoff settings: a worker's sandbox
// can neither verify the target nor, in a guest space, reach it.
func (t *Transport) ListenStream(ctx context.Context, cfg transport.ListenConfig, sr transport.StreamRouter) (transport.StreamListener, error) {
	r, ok := sr.(*router)
	if !ok || r.t != t {
		return nil, fmt.Errorf("reality: a public listener routes with this transport's own router, not a %T", sr)
	}
	ln, ls, err := t.openListener(ctx, cfg)
	if err != nil {
		return nil, err
	}
	records, err := learnedRecords(upstreamRecords{}, ls.target.String(), ls.names)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	handoff, err := json.Marshal(handoffSettings{Listener: cfg.Settings, Records: records})
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("reality: handoff settings: %w", err)
	}
	return &publicListener{Listener: ln, r: r, settings: ls, handoff: handoff, gate: newGate(t, ls.target)}, nil
}

// handoffSettings is what a worker's Handoff gets from the supervisor's
// public listener: its settings and what REALITY learned of the target's
// post-handshake records, by REALITY's key. It never leaves the node: the
// supervisor and its workers are one binary (the IPC version says so), so
// the encoding is plain JSON.
type handoffSettings struct {
	Listener []byte           `json:"listener"`
	Records  map[string][]int `json:"records"`
}

// learnedRecords reads what REALITY learned of dest's post-handshake
// records for every server name and ALPN; detect must have succeeded.
func learnedRecords(store recordsStore, dest string, names map[string]bool) (map[string][]int, error) {
	out := map[string][]int{}
	for name := range names {
		for alpn := range detectedALPNs {
			key := recordsKey(dest, name, alpn)
			v, _ := store.load(key)
			lens, ok := v.([]int)
			if !ok {
				return nil, fmt.Errorf("reality: target %s: no records learned under %q", dest, key)
			}
			out[key] = lens
		}
	}
	return out, nil
}

// publicListener is a supervisor's public reality listener: the settings
// its router opens hellos with, and its gate, which holds the connections
// being decided or spliced to the target and closes them with it.
type publicListener struct {
	net.Listener
	r        *router
	settings listenSettings
	handoff  []byte
	gate     *gate
}

var _ transport.StreamListener = (*publicListener)(nil)

func (pl *publicListener) HandoffSettings() []byte { return pl.handoff }

// Camouflage is reality's own: a connection turned away is spliced to the
// target, what was read of it sent first.
func (pl *publicListener) Camouflage() transport.Camouflage { return targetSplice{pl.gate} }

func (pl *publicListener) Close() error {
	err := pl.Listener.Close()
	pl.gate.close()
	return err
}

// RouteStream implements transport.StreamListener as a standalone
// listener serves a connection up to the decision: the target is dialled
// at accept and gets the hello as it arrives, all of it but the last
// byte until the router decided; what fails is spliced to the target by
// the gate. What authenticates is handed over with that target
// connection. waiting is called once the mirror is up. A read deadline on
// conn (the supervisor's bound) passing before the hello was whole leaves
// the connection spliced to the target, which can then end it as the
// site would.
func (pl *publicListener) RouteStream(conn net.Conn, serves func(transport.Identity) bool, waiting func()) (transport.StreamHandoff, transport.StreamVerdict) {
	var (
		peer    transport.Identity
		verdict = transport.StreamUnknown
	)
	p, d := pl.gate.decide(conn, func(record []byte) bool {
		_, peer, verdict = pl.r.check.check(pl.settings, record, pl.r.lookup, serves)
		return verdict == transport.StreamRouted
	}, waiting)
	switch d {
	case boundClosed:
		return transport.StreamHandoff{}, transport.StreamBoundClosed
	case turnedAway:
		return transport.StreamHandoff{Peer: peer}, verdict
	}
	pl.gate.live.untrack(conn, p.target)
	return transport.StreamHandoff{Peer: peer, Conn: conn, Consumed: p.record, Target: p.target, TargetRead: p.held}, transport.StreamRouted
}

// targetSplice is a public listener's camouflage: the connection is
// spliced to the target, raw and whole, under the listener's splice
// bound.
type targetSplice struct{ g *gate }

func (targetSplice) Datagram([]byte, net.Addr) {}

func (c targetSplice) Stream(conn net.Conn, consumed []byte) { c.g.turnAway(conn, consumed) }
