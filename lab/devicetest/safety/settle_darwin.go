package safety

import (
	"context"
	"fmt"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// settle waits for the host to settle after the undos, in this order: no
// thinkpol process runs (an agent's close releases its pf reference last,
// and that release can turn pf off), the guard's pf reference is
// released, and only then pf goes back on if the baseline had it on.
func settle(ctx context.Context, h *host) []string {
	notes := []string{waitNoAgent(ctx, h), waitGuardReleased(ctx, h)}
	return append(notes, pfBackOn(ctx, h)...)
}

// waitNoAgent waits up to 60 s for no thinkpol process to run.
func waitNoAgent(ctx context.Context, h *host) string {
	for i := 0; ; i++ {
		pids, err := processesNamed("thinkpol")
		switch {
		case err != nil:
			return "processes unreadable: " + err.Error()
		case len(pids) == 0:
			return "no thinkpol agent runs"
		case i >= 60 || ctx.Err() != nil:
			return fmt.Sprintf("a thinkpol process still runs after 60 s (pids %v): stop it, then run devicetest restore", pids)
		}
		h.beat()
		time.Sleep(time.Second)
	}
}

// waitGuardReleased waits up to 30 s for the guard's record to name no
// reference of this boot (one of an earlier boot holds nothing).
func waitGuardReleased(ctx context.Context, h *host) string {
	for i := 0; ; i++ {
		held, err := firewall.GuardReferenceHeld(netcfg.StateDir)
		switch {
		case err != nil:
			return "the guard's record is unreadable: " + err.Error()
		case !held:
			return "the guard holds no pf reference"
		case i >= 30 || ctx.Err() != nil:
			return "the guard still holds a pf reference after 30 s: run thinkpol's rollback (thinkpol up -connect=false, then stop it)"
		}
		h.beat()
		time.Sleep(time.Second)
	}
}

// pfBackOn turns pf back on if the baseline had it on and it is off now:
// the one change a restore makes that no journal entry names, since it
// puts back what the baseline recorded. It never turns pf off.
func pfBackOn(ctx context.Context, h *host) []string {
	if h.baseline == nil {
		return nil
	}
	now, err := h.read(ctx, "pf-info")
	if err != nil {
		return []string{"pf's state: " + err.Error()}
	}
	base := h.baseline.Lines["pf-info"]
	if len(base) != 1 || base[0] != "Status: Enabled" || len(now) != 1 || now[0] != "Status: Disabled" {
		return []string{fmt.Sprintf("pf at the baseline: %v; now: %v", base, now)}
	}
	argv := []string{pfctlPath, "-e"}
	out := run(ctx, argv, nil)
	h.saveOutput(fmt.Sprintf("restore/pfctl-e-%d", time.Now().UnixNano()), argv, out)
	if out.Code != 0 || out.Err != "" {
		return []string{"pf was off and the baseline had it on; pfctl -e failed: " + failed(out).Error()}
	}
	return []string{"pf was off and the baseline had it on: turned back on (pfctl -e)"}
}
