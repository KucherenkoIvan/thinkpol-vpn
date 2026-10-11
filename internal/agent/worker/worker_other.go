//go:build !linux || android

package worker

import (
	"context"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Run returns ErrUnsupported.
func Run(context.Context, netmap.SpaceID, Serve) error { return ErrUnsupported }
