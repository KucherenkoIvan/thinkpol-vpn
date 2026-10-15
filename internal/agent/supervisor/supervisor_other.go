//go:build !linux || android

package supervisor

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"

// Supervisor runs one worker per space; only on Linux.
type Supervisor struct{}

// New returns ErrUnsupported.
func New(Options) (*Supervisor, error) { return nil, ErrUnsupported }

func (*Supervisor) SetSpaces([]Space) error        { return ErrUnsupported }
func (*Supervisor) SetListeners([]Listener) error  { return ErrUnsupported }
func (*Supervisor) Listeners() []ListenerInfo      { return nil }
func (*Supervisor) Workers() []WorkerInfo          { return nil }
func (*Supervisor) Output(netmap.SpaceID) []string { return nil }
func (*Supervisor) Close() error                   { return nil }
func (*Supervisor) Egress() EgressInfo             { return EgressInfo{Err: ErrUnsupported.Error()} }
