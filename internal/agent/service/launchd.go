package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Launchd is macOS's service manager: a daemon in the system domain,
// PlistPath, the group made with dseditgroup (Directory Services).
type Launchd struct {
	// Poll is how often a stop reads launchd's state (`launchctl print`)
	// while it waits for the daemon to be gone.
	Poll time.Duration
	// StopWait bounds that wait; zero is StopTimeoutSeconds (the plist's
	// ExitTimeOut, after which launchd kills the agent) and a margin.
	StopWait time.Duration
}

// target is the daemon in launchctl's system domain.
const target = "system/" + Label

// Present looks for /Library/LaunchDaemons.
func (Launchd) Present(root string) error {
	if fi, err := os.Stat(filepath.Join(root, filepath.Dir(PlistPath))); err != nil || !fi.IsDir() {
		return errors.New("no /Library/LaunchDaemons: this isn't macOS's launchd")
	}
	return nil
}

func (Launchd) DefinitionPath() string { return PlistPath }

func (Launchd) Render(d Definition) []byte { return LaunchdPlist(d) }

// Start stops a loaded daemon (it is started again on the new plist),
// enables it only if someone disabled it (a fresh install leaves no
// override), and bootstraps the plist, which starts it (RunAtLoad).
func (l Launchd) Start(ctx context.Context, run Runner) error {
	if err := l.Stop(ctx, run); err != nil {
		return err
	}
	out, err := run(ctx, "launchctl", "print-disabled", "system")
	if err != nil {
		return err
	}
	if disabled(out) {
		if _, err := run(ctx, "launchctl", "enable", target); err != nil {
			return err
		}
	}
	_, err = run(ctx, "launchctl", "bootstrap", "system", PlistPath)
	return err
}

// disabled says whether `launchctl print-disabled system` lists the
// daemon as disabled ("=> disabled", or "=> true" on older macOS).
func disabled(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if ok && strings.TrimSpace(k) == `"`+Label+`"` {
			v = strings.TrimSpace(v)
			return v == "disabled" || v == "true"
		}
	}
	return false
}

// Reload does nothing: launchd reads the plist when it bootstraps the
// system domain, at the next boot.
func (Launchd) Reload(context.Context, Runner) error { return nil }

// Stop boots the daemon out (SIGTERM to the agent, SIGKILL after
// ExitTimeOut) and waits until launchd no longer has it: bootout may
// return before the job is gone. A daemon that wasn't loaded is stopped;
// a bootout that failed with the daemon still there is the error.
func (l Launchd) Stop(ctx context.Context, run Runner) error {
	if !loaded(ctx, run) {
		return nil
	}
	_, bootErr := run(ctx, "launchctl", "bootout", target)
	wait := l.StopWait
	if wait == 0 {
		wait = (StopTimeoutSeconds + 15) * time.Second
	}
	deadline := time.Now().Add(wait)
	for loaded(ctx, run) {
		if bootErr != nil {
			return bootErr
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("launchd still has %s after %v", target, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(l.Poll):
		}
	}
	return nil
}

func loaded(ctx context.Context, run Runner) bool {
	_, err := run(ctx, "launchctl", "print", target)
	return err == nil
}

func (Launchd) Forget(context.Context, Runner) error { return nil }

func (Launchd) EnsureGroup(ctx context.Context, run Runner, group string) error {
	if _, err := run(ctx, "dseditgroup", "-o", "read", group); err == nil {
		return nil
	}
	_, err := run(ctx, "dseditgroup", "-o", "create", "-r", "thinkpol local API", group)
	return err
}

// AddToGroup adds the user unless `dseditgroup -o checkmember` finds them
// in it: a second add may fail.
func (Launchd) AddToGroup(ctx context.Context, run Runner, user, group string) error {
	if _, err := run(ctx, "dseditgroup", "-o", "checkmember", "-m", user, group); err == nil {
		return nil
	}
	_, err := run(ctx, "dseditgroup", "-o", "edit", "-a", user, "-t", "user", group)
	return err
}
