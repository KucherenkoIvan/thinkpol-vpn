package agent

// hostLockPath is the host's agent lock, next to netcfg's locks (and the
// same file as /var/run/thinkpol/agent.lock, macOS's path, where /var/run
// links to /run).
const hostLockPath = "/run/thinkpol/agent.lock"
