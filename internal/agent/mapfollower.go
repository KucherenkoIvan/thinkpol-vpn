package agent

import (
	"errors"
	"log/slog"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// mapFollower is the map-following state of one node of a space: its
// current map, its section in it, and whether it was removed from the
// space. Device mode (the data plane's runner), server mode (the
// supervisor's spaces) and a node waiting while removed all take envelopes
// through one, so what a newer map means can't drift between them. Its
// caller tells the node's removal and return as events, once its status
// shows them.
type mapFollower struct {
	log  *slog.Logger
	keys NodeKeys
	// report counts the maps refused (Status.MapsRefused): invalid ones
	// and those not for this node, never one merely not newer (the same
	// map read again); nil counts nowhere.
	report *report

	cur     *netmap.Map
	section netmap.Section
	removed bool

	// removedMsg completes the removal warning: "removed from space: the
	// map has no section for this node; <removedMsg>", said once per
	// removal, about what stopping means here.
	removedMsg string

	// device is a follower in device mode, which never runs a server's
	// section (PRD A4): mismatch is set while the section held is one,
	// and the node runs nothing of the map, as while removed.
	device   bool
	mismatch bool
}

// modeMismatchMsg is what a device-mode node says when the map makes it a
// server: a server box whose node file lost its mode is left alone.
const modeMismatchMsg = `the map makes this node a server, but it runs in device mode, which runs no server: ` +
	`it carries nothing and leaves the host's network alone; set "mode": "server" in node.json (or -mode server) and restart`

// take takes a newer map if it is one (valid, signed by the space,
// newer), and reports whether it did; removed when that map removes the
// node from its space (not when it was out already), back when it has the
// node's section again after a removal: the caller says so (sayBack) once
// it knows what the node is back as. A taken map without a section for
// the node keeps the node's last section; a taken section sets mismatch
// (checkKind), and on a server logs a kind change against the last one
// held.
func (f *mapFollower) take(envelope []byte) (taken, removed, back bool) {
	m, err := f.cur.Next(envelope)
	if errors.Is(err, netmap.ErrNotNewer) {
		f.log.Debug("map not newer, ignored", "version", f.cur.Header().Version)
		return false, false, false
	}
	if err != nil {
		f.log.Warn("map refused, keeping the current one", "version", f.cur.Header().Version, "err", err)
		f.refused()
		return false, false, false
	}
	section, err := openSection(m, f.keys)
	if errors.Is(err, netmap.ErrNotRecipient) {
		// A valid newer map without the node: it was removed. The map
		// is taken, so no older one that has the node can come back.
		return true, f.markRemoved(m), false
	}
	if err != nil {
		f.log.Error("map refused, keeping the current one", "version", f.cur.Header().Version, "err", err)
		f.refused()
		return false, false, false
	}
	// The mode never follows the kind: a device's mismatch says what a
	// change means there. Kind 0 is no kind held yet, a follower that
	// starts while the node is out of its space.
	if !f.device && f.section.Node.Kind != 0 && section.Node.Kind != f.section.Node.Kind {
		f.log.Warn("the map changes this node's kind; the node's mode is its own (-mode, node.json) and doesn't follow it", "kind", section.Node.Kind)
	}
	back = f.removed
	f.cur, f.section, f.removed = m, section, false
	f.checkKind()
	return true, false, back
}

// out is whether the node runs nothing of the map: removed from its space,
// or a server's section in device mode.
func (f *mapFollower) out() bool { return f.removed || f.mismatch }

// checkKind sets mismatch from the section held, and says when it changes.
func (f *mapFollower) checkKind() {
	was := f.mismatch
	f.mismatch = f.device && f.section.Node.Kind == netmap.NodeServer
	switch {
	case f.mismatch && !was:
		f.log.Error(modeMismatchMsg, "version", f.cur.Header().Version)
	case was && !f.mismatch:
		f.log.Info("the map makes this node a device again", "version", f.cur.Header().Version)
	}
}

// refused counts a map not taken in the report.
func (f *mapFollower) refused() { f.report.set(func(p *report) { p.mapsRefused++ }) }

// sayBack logs that the node is back in its space, at the current map's
// version, with attrs.
func (f *mapFollower) sayBack(attrs ...any) {
	f.log.Info("back in space", append([]any{"version", f.cur.Header().Version}, attrs...)...)
}

// markRemoved takes m, a map without the node's section (a newer one in
// take, the starting one where a node starts removed), and says once per
// removal what the node does meanwhile; now is whether it was in its space
// until m.
func (f *mapFollower) markRemoved(m *netmap.Map) (now bool) {
	f.cur = m
	if f.removed {
		return false
	}
	f.removed, f.mismatch = true, false
	f.log.Warn("removed from space: the map has no section for this node; "+f.removedMsg,
		"version", m.Header().Version)
	return true
}
