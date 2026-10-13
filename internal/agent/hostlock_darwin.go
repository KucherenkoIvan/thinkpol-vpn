package agent

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"

// hostLockPath is the host's agent lock, next to netcfg's locks and
// records. macOS has no /run, and its /var/run is group-writable
// (root:daemon 0775, not sticky): /private/var/db is root's alone all the
// way up.
const hostLockPath = netcfg.StateDir + "/agent.lock"
