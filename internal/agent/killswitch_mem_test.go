package agent

import (
	"context"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
)

// memKillSwitches is a host's kill switch in memory: what any of its
// KillSwitches put in place stays until one of them closes it, as the
// host's table outlives a run.
type memKillSwitches struct {
	mu        sync.Mutex
	in        *firewall.KillSwitchRules
	fail      error // Apply fails with it
	failClose error // Close fails with it
}

func (h *memKillSwitches) new() KillSwitch { return memKillSwitch{h} }

// rules is what is in place; nil: nothing.
func (h *memKillSwitches) rules() *firewall.KillSwitchRules {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.in
}

func (h *memKillSwitches) put(r *firewall.KillSwitchRules) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.in = r
}

func (h *memKillSwitches) failWith(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fail = err
}

func (h *memKillSwitches) failCloseWith(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failClose = err
}

type memKillSwitch struct{ h *memKillSwitches }

func (k memKillSwitch) Apply(_ context.Context, r firewall.KillSwitchRules) error {
	k.h.mu.Lock()
	defer k.h.mu.Unlock()
	if k.h.fail != nil {
		return k.h.fail
	}
	k.h.in = &r
	return nil
}

func (k memKillSwitch) Close() error {
	k.h.mu.Lock()
	defer k.h.mu.Unlock()
	if k.h.failClose != nil {
		return k.h.failClose
	}
	k.h.in = nil
	return nil
}
