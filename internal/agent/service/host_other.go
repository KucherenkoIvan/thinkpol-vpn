//go:build (!linux || android) && !darwin

package service

import (
	"errors"
	"io"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// HostInstaller refuses on this OS: the Windows service is TP-047's.
func HostInstaller(io.Writer, agent.Platform) (Installer, error) {
	return Installer{}, errors.ErrUnsupported
}

// CheckRoot refuses on this OS.
func CheckRoot() error { return errors.ErrUnsupported }

// InstallingUser is no one on this OS.
func InstallingUser() string { return "" }
