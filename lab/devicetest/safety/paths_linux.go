package safety

import "os"

// DefaultStateDir is root's directory for runs' journals.
const DefaultStateDir = "/var/lib/thinkpol-devicetest"

const (
	rootCopyBase = "/tmp"
	// hasher prints a file's sha256 first on its line.
	hasher = "/usr/bin/sha256sum"
)

// Tcpdump is tcpdump: the core's captures and the user side's decode of
// them run the same one.
func Tcpdump() string { return firstExisting("/usr/bin/tcpdump", "/usr/sbin/tcpdump") }

// ipPath is iproute2's ip, wherever the distribution put it.
func ipPath() string { return firstExisting("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip") }

// firstExisting is the first of paths that is a regular file (paths[0]
// if none is).
func firstExisting(paths ...string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return paths[0]
}
