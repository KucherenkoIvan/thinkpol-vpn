package localapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

var groupName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// systemGroup looks a group up in Directory Services (`dscl . -read
// /Groups/<name> PrimaryGroupID`), where macOS keeps groups made with
// dscl or System Settings.
func systemGroup(name string) (uint32, bool) {
	if !groupName.MatchString(name) {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), dsTimeout)
	defer cancel()
	out, err := runBounded(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+name, "PrimaryGroupID")
	if err != nil {
		return 0, false
	}
	return parsePrimaryGroupID(string(out))
}

// parsePrimaryGroupID reads dscl's "PrimaryGroupID: 501".
func parsePrimaryGroupID(out string) (uint32, bool) {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PrimaryGroupID:"); ok {
			gid, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			return uint32(gid), err == nil
		}
	}
	return 0, false
}

// systemMembership asks Directory Services (`dsmemberutil
// checkmembership`), which the file system's group checks also ask:
// unlike LOCAL_PEERCRED, it isn't limited to the login's groups or to
// their first 16.
func systemMembership() Membership {
	return newCachedMembership(dsmemberutil{run: runBounded})
}

// runBounded runs name, killed when ctx ends; dsWaitDelay after that it
// kills it again and stops reading its output.
func runBounded(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = dsWaitDelay
	return cmd.Output()
}

// dsWaitDelay bounds the wait for a Directory Services tool that was
// killed at its deadline.
const dsWaitDelay = time.Second

// dsmemberutil is a [Membership] that asks dsmemberutil by numbers,
// through run.
type dsmemberutil struct {
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (d dsmemberutil) IsMember(ctx context.Context, uid, gid uint32) (bool, error) {
	out, err := d.run(ctx, "/usr/bin/dsmemberutil", "checkmembership",
		"-u", strconv.FormatUint(uint64(uid), 10), "-g", strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		if ee := (*exec.ExitError)(nil); errors.As(err, &ee) && len(bytes.TrimSpace(ee.Stderr)) > 0 {
			return false, fmt.Errorf("dsmemberutil: %w: %s", err, clip(agent.Sanitize(string(bytes.TrimSpace(ee.Stderr)))))
		}
		return false, fmt.Errorf("dsmemberutil: %w", err)
	}
	return parseCheckMembership(string(out))
}

// parseCheckMembership reads dsmemberutil's answer; anything but its two
// sentences is an error, which quotes at most unexpectedMax bytes of it.
func parseCheckMembership(out string) (bool, error) {
	out = strings.TrimSpace(out)
	switch out {
	case "user is a member of the group":
		return true, nil
	case "user is not a member of the group":
		return false, nil
	}
	return false, fmt.Errorf("dsmemberutil: unexpected answer %q", clip(out))
}

// clip cuts what dsmemberutil printed to unexpectedMax bytes, so an error
// quoting it stays one log line.
func clip(s string) string {
	if len(s) > unexpectedMax {
		return s[:unexpectedMax] + "…"
	}
	return s
}

const unexpectedMax = 200
