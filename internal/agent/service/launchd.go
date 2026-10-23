package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	// launchd may refuse a bootstrap just after the job it replaces is
	// gone ("Bootstrap failed: 5: Input/output error"), and may say so of
	// a bootstrap that loaded the job all the same: after an EIO, a job
	// launchd shows is started; else it is retried briefly. Any other
	// refusal is the error.
	for try := 0; ; try++ {
		out, err := run(ctx, "launchctl", "bootstrap", "system", PlistPath)
		if err == nil || !inputOutputError(out, err) {
			return err
		}
		there, perr := present(ctx, run)
		if perr != nil {
			return errors.Join(err, perr)
		}
		if there {
			return nil
		}
		if try == bootstrapTries-1 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(l.Poll):
		}
	}
}

// bootstrapTries bounds Start's bootstraps refused with EIO.
const bootstrapTries = 5

// inputOutputError says whether a failed bootstrap was launchd's EIO:
// exit status 5, or its "Input/output error".
func inputOutputError(out string, err error) bool {
	var x *exec.ExitError
	if errors.As(err, &x) && x.ExitCode() == 5 {
		return true
	}
	return strings.Contains(out+" "+err.Error(), "Input/output error")
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
// ExitTimeOut) and waits until launchd no longer has it, whatever bootout
// said: it may return before the job is gone, or fail with a slow exit
// ("Operation now in progress") that ends all the same. bootout's error
// is reported only if the daemon outlives the wait; a `launchctl print`
// that fails for another reason than no such service fails the stop.
func (l Launchd) Stop(ctx context.Context, run Runner) error {
	there, err := present(ctx, run)
	if err != nil || !there {
		return err
	}
	_, bootErr := run(ctx, "launchctl", "bootout", target)
	wait := l.StopWait
	if wait == 0 {
		wait = (StopTimeoutSeconds + 15) * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		there, err := present(ctx, run)
		if err != nil || !there {
			return err
		}
		if time.Now().After(deadline) {
			if bootErr != nil {
				return fmt.Errorf("launchd still has %s after %v: %w", target, wait, bootErr)
			}
			return fmt.Errorf("launchd still has %s after %v", target, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(l.Poll):
		}
	}
}

// State reads whether launchd has the daemon (`launchctl print`) and
// whether an override disables it (`launchctl print-disabled`): a daemon
// launchd doesn't have is bootstrapped at the next boot unless disabled.
func (Launchd) State(ctx context.Context, run Runner) string {
	loaded := "can't say whether launchd has the daemon"
	if there, err := present(ctx, run); err == nil {
		loaded = "launchd doesn't have the daemon loaded"
		if there {
			loaded = "launchd has the daemon loaded"
		}
	}
	override := "its overrides couldn't be read"
	if out, err := run(ctx, "launchctl", "print-disabled", "system"); err == nil {
		override = "no override disables it"
		if disabled(out) {
			override = "an override disables it"
		}
	}
	return loaded + ", " + override
}

// Remove is Stop: a daemon booted out isn't launchd's any more until the
// plist is bootstrapped again (at boot, if it is still there).
func (l Launchd) Remove(ctx context.Context, run Runner) error { return l.Stop(ctx, run) }

// present says whether launchd has the daemon (`launchctl print`): no
// such service is false; any other failure (a cancelled context, a
// timeout, launchctl itself) is the error.
func present(ctx context.Context, run Runner) (bool, error) {
	out, err := run(ctx, "launchctl", "print", target)
	switch {
	case err == nil:
		return true, nil
	case noSuchService(out, err):
		return false, nil
	}
	return false, fmt.Errorf("asking launchd for %s: %w", target, err)
}

// noSuchService says whether a failed `launchctl print` found no such
// service: exit status 113, or launchctl's "Could not find service".
func noSuchService(out string, err error) bool {
	var x *exec.ExitError
	if errors.As(err, &x) && x.ExitCode() == 113 {
		return true
	}
	return strings.Contains(strings.ToLower(out+" "+err.Error()), "could not find service")
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
