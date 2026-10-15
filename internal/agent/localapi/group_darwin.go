package localapi

import (
	"context"
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
