package agent

import "errors"

// ErrAnotherAgent: another node agent holds the host's agent lock
// (HostLock).
var ErrAnotherAgent = errors.New("another thinkpol agent is running on this host")
