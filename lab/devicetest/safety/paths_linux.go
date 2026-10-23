package safety

import "os"

// ipPath is iproute2's ip, wherever the distribution put it.
func ipPath() string { return firstExisting("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip") }

func tcpdump() string { return firstExisting("/usr/bin/tcpdump", "/usr/sbin/tcpdump") }

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

// hasher prints a file's sha256 first on its line.
const hasher = "/usr/bin/sha256sum"
