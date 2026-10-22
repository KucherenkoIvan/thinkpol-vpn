package service

import (
	"context"
	"time"
)

// Launchd is macOS's service manager: a daemon in the system domain,
// PlistPath, the group made with dseditgroup (Directory Services).
type Launchd struct {
	// BootstrapRetry is how long Start waits between bootstrap tries: a
	// service just booted out may still be going.
	BootstrapRetry time.Duration
}

// target is the daemon in launchctl's system domain.
const target = "system/" + Label

func (Launchd) DefinitionPath() string { return PlistPath }

func (Launchd) Render(d Definition) []byte { return LaunchdPlist(d) }

// Start boots a loaded daemon out (it is restarted on the new plist) and
// bootstraps the plist, which starts it (RunAtLoad).
func (l Launchd) Start(ctx context.Context, run Runner) error {
	_, _ = run(ctx, "launchctl", "bootout", target) // not loaded: nothing to do
	if _, err := run(ctx, "launchctl", "enable", target); err != nil {
		return err
	}
	var err error
	for range 10 {
		if _, err = run(ctx, "launchctl", "bootstrap", "system", PlistPath); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(l.BootstrapRetry):
		}
	}
	return err
}

// Reload does nothing: launchd reads the plist when it bootstraps the
// system domain, at the next boot.
func (Launchd) Reload(context.Context, Runner) error { return nil }

// Stop boots the daemon out, which stops the agent (SIGTERM, then
// SIGKILL after ExitTimeOut). A daemon that wasn't loaded is stopped.
func (Launchd) Stop(ctx context.Context, run Runner) error {
	_, err := run(ctx, "launchctl", "bootout", target)
	if err == nil {
		return nil
	}
	if _, perr := run(ctx, "launchctl", "print", target); perr != nil {
		return nil // not loaded
	}
	return err
}

func (Launchd) Forget(context.Context, Runner) error { return nil }

func (Launchd) EnsureGroup(ctx context.Context, run Runner, group string) error {
	if _, err := run(ctx, "dseditgroup", "-o", "read", group); err == nil {
		return nil
	}
	_, err := run(ctx, "dseditgroup", "-o", "create", "-r", "thinkpol local API", group)
	return err
}

func (Launchd) AddToGroup(ctx context.Context, run Runner, user, group string) error {
	_, err := run(ctx, "dseditgroup", "-o", "edit", "-a", user, "-t", "user", group)
	return err
}

func (Launchd) DeleteGroup(ctx context.Context, run Runner, group string) error {
	if _, err := run(ctx, "dseditgroup", "-o", "read", group); err != nil {
		return nil // no such group
	}
	_, err := run(ctx, "dseditgroup", "-o", "delete", group)
	return err
}
