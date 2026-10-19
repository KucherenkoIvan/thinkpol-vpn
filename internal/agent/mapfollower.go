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
// through one, so what a newer map means can't drift between them.
type mapFollower struct {
	log  *slog.Logger
	keys NodeKeys

	cur     *netmap.Map
	section netmap.Section
	removed bool

	// removedMsg completes the removal warning: "removed from space: the
	// map has no section for this node; <removedMsg>", said once per
	// removal, about what stopping means here.
	removedMsg string
}

// take takes a newer map if it is one (valid, signed by the space,
// newer), and reports whether it did. A taken map without a section for
// the node (it was removed from the space) keeps the node's last section,
// so a later one that has it again is a back-in-space; a taken section
// logs a kind change first, against the last one held.
func (f *mapFollower) take(envelope []byte) bool {
	m, err := f.cur.Next(envelope)
	if errors.Is(err, netmap.ErrNotNewer) {
		f.log.Debug("map not newer, ignored", "version", f.cur.Header().Version)
		return false
	}
	if err != nil {
		f.log.Warn("map refused, keeping the current one", "version", f.cur.Header().Version, "err", err)
		return false
	}
	section, err := openSection(m, f.keys)
	if errors.Is(err, netmap.ErrNotRecipient) {
		// A valid newer map without the node: it was removed. The map
		// is taken, so no older one that has the node can come back.
		f.markRemoved(m)
		return true
	}
	if err != nil {
		f.log.Error("map refused, keeping the current one", "version", f.cur.Header().Version, "err", err)
		return false
	}
	// A kind held is the running node's: it can't change (it restarts
	// to). Kind 0 is no kind held yet, a follower that starts while the
	// node is out of its space.
	if f.section.Node.Kind != 0 && section.Node.Kind != f.section.Node.Kind {
		f.log.Warn("the map changes this node's kind; restart the node to change its mode", "kind", section.Node.Kind)
	}
	f.cur, f.section = m, section
	if f.removed {
		f.removed = false
		f.log.Info("back in space", "version", m.Header().Version)
	}
	return true
}

// markRemoved takes m, a map without the node's section (a newer one in
// take, the starting one where a node starts removed), and says once per
// removal what the node does meanwhile.
func (f *mapFollower) markRemoved(m *netmap.Map) {
	f.cur = m
	if f.removed {
		return
	}
	f.removed = true
	f.log.Warn("removed from space: the map has no section for this node; "+f.removedMsg,
		"version", m.Header().Version)
}
