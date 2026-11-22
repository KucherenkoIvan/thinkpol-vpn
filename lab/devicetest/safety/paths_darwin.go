package safety

// defaultStateDir is root's directory for runs' journals: root's alone all
// the way up.
const defaultStateDir = "/private/var/db/thinkpol-devicetest"

// The commands and files the core uses, by absolute path: never looked up.
const (
	rootCopyBase = "/private/tmp"
	pfctlPath    = "/sbin/pfctl"
	scutilPath   = "/usr/sbin/scutil"
	pfConfPath   = "/etc/pf.conf"
	// hasher prints a file's sha256 first on its line.
	hasher = "/usr/bin/shasum -a 256"
)

// Tcpdump is tcpdump: the core's captures and the user side's decode of
// them run the same one.
func Tcpdump() string { return "/usr/sbin/tcpdump" }
