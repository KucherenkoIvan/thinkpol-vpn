package safety

// The commands the core runs, by absolute path: never looked up.
const (
	pfctlPath   = "/sbin/pfctl"
	scutilPath  = "/usr/sbin/scutil"
	pfConfPath  = "/etc/pf.conf"
	tcpdumpPath = "/usr/sbin/tcpdump"
)

func tcpdump() string { return tcpdumpPath }

// hasher prints a file's sha256 first on its line.
const hasher = "/usr/bin/shasum -a 256"
