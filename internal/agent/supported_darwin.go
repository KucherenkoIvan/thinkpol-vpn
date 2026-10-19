package agent

import "fmt"

// supported reports whether this OS can run a node's data plane in mode:
// a device's, not a server's, whose supervisor and per-space workers need
// Linux's namespaces. Nothing is configured before this check.
func supported(mode Mode) error {
	if mode == ModeServer {
		return fmt.Errorf("%w: server mode needs Linux; run this node as a device (-mode device)", ErrUnsupported)
	}
	return nil
}
