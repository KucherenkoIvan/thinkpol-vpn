package safety

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// DefaultStateDir is root's directory for runs' journals: root's alone all
// the way up.
const DefaultStateDir = "/private/var/db/thinkpol-devicetest"

// rootCopyBase is where the root copy of the binary goes.
const rootCopyBase = "/private/tmp"

// settle waits for the host to settle after the undos, in the runbook's
// order: no thinkpol agent runs (its Close releases its pf reference
// last, and that can turn pf off), the guard's reference is released,
// and only then pf is turned back on if the baseline had it on.
func settle(ctx context.Context, h *Host) []string {
	notes := []string{waitStop(ctx, h), waitRelease(ctx, h)}
	return append(notes, pfRestore(ctx, h)...)
}

// waitStop waits up to 60 s for no thinkpol process to run.
func waitStop(ctx context.Context, h *Host) string {
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

// waitRelease waits up to 30 s for the guard's record of its pf
// reference to go.
func waitRelease(ctx context.Context, h *Host) string {
	path := filepath.Join(netcfg.StateDir, firewall.TokenRecordName)
	for i := 0; ; i++ {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return "the guard's pf reference is released"
		}
		if i >= 30 || ctx.Err() != nil {
			return path + " is still there after 30 s: run thinkpol's rollback (thinkpol up -connect=false, then stop it)"
		}
		h.beat()
		time.Sleep(time.Second)
	}
}

// pfRestore turns pf back on if the baseline had it on and it is off
// now. It never turns pf off.
func pfRestore(ctx context.Context, h *Host) []string {
	if h.Baseline == nil {
		return nil
	}
	now, err := h.read(ctx, "pf-info")
	if err != nil {
		return []string{"pf's state: " + err.Error()}
	}
	base := h.Baseline.Lines["pf-info"]
	if len(base) != 1 || base[0] != "Status: Enabled" || len(now) != 1 || now[0] != "Status: Disabled" {
		return []string{fmt.Sprintf("pf at the baseline: %v; now: %v", base, now)}
	}
	argv := []string{pfctlPath, "-e"}
	out := run(ctx, argv, nil)
	h.saveOutput(fmt.Sprintf("restore/pfctl-e-%d", time.Now().UnixNano()), argv, out)
	return []string{"pf was off and the baseline had it on: turned back on (pfctl -e)"}
}
