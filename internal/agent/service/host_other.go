//go:build !linux && !darwin

package service

import (
	"errors"
	"io"
)

// HostInstaller refuses on this OS: the Windows service is TP-047's.
func HostInstaller(io.Writer) (Installer, error) { return Installer{}, errors.ErrUnsupported }

// CheckRoot refuses on this OS.
func CheckRoot() error { return errors.ErrUnsupported }

// InstallingUser is no one on this OS.
func InstallingUser() string { return "" }
