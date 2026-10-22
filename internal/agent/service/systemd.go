package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// Stop disables the unit and stops it, waiting for the agent to exit
// (TimeoutStopSec, then systemd kills it).
func (Systemd) Stop(ctx context.Context, run Runner) error {
	_, err := run(ctx, "systemctl", "disable", "--now", UnitName)
	return err
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
