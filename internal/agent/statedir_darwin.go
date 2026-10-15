package agent

// DefaultStateDir is where a node keeps its keys and its map, and nothing
// else (PRD S1). The state directory is opened through the trusted walk,
// which refuses symlinks on the way: /var is one (to private/var), so the
// path names the real directory.
const DefaultStateDir = "/private/var/lib/thinkpol"
