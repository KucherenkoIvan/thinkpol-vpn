package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
// (TimeoutStopSec, then systemd kills it). systemd loads a unit file it
// hasn't read yet for the stop (an install that died between writing it
// and starting it): systemd 252 answers 0 (seen in the lab). One that
// doesn't load it answers "Unit … not loaded" (exit 5): nothing of the
// unit runs, which is what was asked.
func (Systemd) Stop(ctx context.Context, run Runner) error {
	return stopped(run(ctx, "systemctl", "stop", UnitName))
}

// Remove disables the unit and stops it, as Stop waits and reads "not
// loaded".
func (Systemd) Remove(ctx context.Context, run Runner) error {
	return stopped(run(ctx, "systemctl", "disable", "--now", UnitName))
}

// stopped is a stop's outcome, "not loaded" read as stopped.
func stopped(out string, err error) error {
	if err == nil || notLoaded(out, err) {
		return nil
	}
	return err
}

// notLoaded says whether systemctl failed for a unit it doesn't have:
// exit status 5; its " not loaded" text counts only when no exit status
// is known.
func notLoaded(out string, err error) bool {
	var x *exec.ExitError
	if errors.As(err, &x) {
		return x.ExitCode() == 5
	}
	return strings.Contains(out+" "+err.Error(), " not loaded")
}

// State reads `systemctl is-enabled` and `is-active`. Each prints its
// state with a non-zero exit too, on the output's last line (a warning,
// such as a unit file changed on disk, may come before it); only a word
// systemd uses for that read counts, anything else (no systemctl, no
// bus) is said to be unread. A unit whose start failed may be started
// again by systemd itself (Restart=always): "activating" says so.
func (Systemd) State(ctx context.Context, run Runner) string {
	read := func(verb string, words []string) (string, bool) {
		out, _ := run(ctx, "systemctl", verb, UnitName)
		lines := strings.Split(strings.TrimSpace(out), "\n")
		last := strings.TrimSpace(lines[len(lines)-1])
		return last, slices.Contains(words, last)
	}
	enabled, okEnabled := read("is-enabled", enabledStates)
	active, okActive := read("is-active", activeStates)
	switch {
	case !okEnabled && !okActive:
		return "systemd couldn't be asked about the unit"
	case !okEnabled:
		return fmt.Sprintf("systemd reports the unit %s; whether it is enabled couldn't be read", active) + retried(active)
	case !okActive:
		return fmt.Sprintf("systemd reports the unit %s; whether it runs couldn't be read", enabled)
	}
	return fmt.Sprintf("systemd reports the unit %s and %s", enabled, active) + retried(active)
}

func retried(active string) string {
	if active == "activating" {
		return " (Restart=always retries it)"
	}
	return ""
}

// The words `systemctl is-enabled` and `is-active` answer with.
var (
	enabledStates = []string{"enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked", "masked-runtime",
		"static", "indirect", "disabled", "generated", "transient", "bad", "not-found"}
	activeStates = []string{"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}
)

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
