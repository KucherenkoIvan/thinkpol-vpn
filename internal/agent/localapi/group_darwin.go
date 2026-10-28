package localapi

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var groupName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// systemGroup looks a group up in Directory Services (`dscl . -read
// /Groups/<name> PrimaryGroupID`), where macOS keeps groups made with
// dscl or System Settings.
func systemGroup(name string) (uint32, bool) {
	if !groupName.MatchString(name) {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+name, "PrimaryGroupID").Output()
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
	return newCachedMembership(dsmemberutil(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}))
}

// dsmemberutil looks membership up by numbers, through run.
func dsmemberutil(run func(ctx context.Context, name string, args ...string) ([]byte, error)) func(ctx context.Context, uid, gid uint32) (bool, error) {
	return func(ctx context.Context, uid, gid uint32) (bool, error) {
		out, err := run(ctx, "/usr/bin/dsmemberutil", "checkmembership",
			"-u", strconv.FormatUint(uint64(uid), 10), "-g", strconv.FormatUint(uint64(gid), 10))
		if err != nil {
			return false, fmt.Errorf("dsmemberutil: %w", err)
		}
		return parseCheckMembership(string(out))
	}
}

// parseCheckMembership reads dsmemberutil's answer; anything but its two
// sentences is an error.
func parseCheckMembership(out string) (bool, error) {
	switch strings.TrimSpace(out) {
	case "user is a member of the group":
		return true, nil
	case "user is not a member of the group":
		return false, nil
	}
	return false, fmt.Errorf("dsmemberutil: unexpected answer %q", strings.TrimSpace(out))
}
