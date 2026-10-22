package main

import (
	"strings"
	"testing"
)

// connect-on-boot is on or off, the same word everywhere; anything else
// is a usage error, before anything looks at the host.
func TestServiceConnectOnBootIsOnOrOff(t *testing.T) {
	for _, args := range [][]string{
		{"service", "install", "-connect-on-boot", "yes"},
		{"service", "install", "-connect-on-boot", "true"},
		{"service", "connect-on-boot", "true"},
	} {
		code, _, stderr := runCLI(t, args...)
		if code != 2 || !strings.Contains(stderr, "on|off") {
			t.Errorf("%v: exit %d\n%s", args, code, stderr)
		}
	}
}
