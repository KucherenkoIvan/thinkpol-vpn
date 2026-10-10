//go:build !linux || android

package netcfg_test

import (
	"errors"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

func TestNewRefusesUnsupportedHosts(t *testing.T) {
	c, err := netcfg.New()
	if !errors.Is(err, errors.ErrUnsupported) || c != nil {
		t.Fatalf("New() = %v, %v; want nil, ErrUnsupported", c, err)
	}
}
