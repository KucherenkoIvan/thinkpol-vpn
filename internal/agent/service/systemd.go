package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Systemd is the service manager of most Linux distributions: the unit
// UnitPath, the group made with groupadd.
type Systemd struct{}

// errNoSystemd: the host doesn't run systemd (OpenRC, a container, WSL1).
var errNoSystemd = errors.New("this host doesn't run systemd (no /run/systemd/system): run thinkpol up under your own service manager")

// Present looks for /run/systemd/system, which systemd makes as it boots
// (sd_booted).
func (Systemd) Present(root string) error {
	if fi, err := os.Stat(filepath.Join(root, "/run/systemd/system")); err != nil || !fi.IsDir() {
		return errNoSystemd
	}
	return nil
}

func (Systemd) DefinitionPath() string { return UnitPath }

func (Systemd) Render(d Definition) []byte { return SystemdUnit(d) }

func (Systemd) Start(ctx context.Context, run Runner) error {
	for _, args := range [][]string{{"daemon-reload"}, {"enable", UnitName}, {"restart", UnitName}} {
		if _, err := run(ctx, "systemctl", args...); err != nil {
			return err
		}
	}
	return nil
}

func (Systemd) Reload(ctx context.Context, run Runner) error {
	_, err := run(ctx, "systemctl", "daemon-reload")
	return err
}

// Stop stops the unit, still enabled, waiting for the agent to exit
// (TimeoutStopSec, then systemd kills it). A unit systemd hasn't loaded
// (an install that died between writing it and starting it) runs
// nothing: it is stopped.
func (Systemd) Stop(ctx context.Context, run Runner) error {
	return stopped(run(ctx, "systemctl", "stop", UnitName))
}

// Remove disables the unit and stops it, as Stop waits; a unit systemd
// hasn't loaded is disabled (systemctl disables first) and stopped.
func (Systemd) Remove(ctx context.Context, run Runner) error {
	return stopped(run(ctx, "systemctl", "disable", "--now", UnitName))
}

// stopped is a stop's outcome: systemd's "Unit … not loaded" (exit
// status 5) means nothing of the unit runs, which is what was asked.
func stopped(out string, err error) error {
	if err == nil || notLoaded(out, err) {
		return nil
	}
	return err
}

func notLoaded(out string, err error) bool {
	var x *exec.ExitError
	if errors.As(err, &x) && x.ExitCode() == 5 {
		return true
	}
	return strings.Contains(out+" "+err.Error(), " not loaded")
}

// Forget reloads the units without it, and forgets a failed state it had.
func (Systemd) Forget(ctx context.Context, run Runner) error {
	if _, err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, _ = run(ctx, "systemctl", "reset-failed", UnitName)
	return nil
}

// EnsureGroup makes a system group; -f succeeds if it exists.
func (Systemd) EnsureGroup(ctx context.Context, run Runner, group string) error {
	_, err := run(ctx, "groupadd", "-f", "-r", group)
	return err
}

// AddToGroup appends the group to the user's (-a: a member stays one).
func (Systemd) AddToGroup(ctx context.Context, run Runner, user, group string) error {
	_, err := run(ctx, "usermod", "-a", "-G", group, user)
	return err
}
