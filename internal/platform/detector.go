package platform

import (
	"runtime"
)

// Platform represents the detected platform
type Platform string

const (
	PlatformDarwin  Platform = "darwin"
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformUnknown Platform = "unknown"
)

// Detect detects the current platform at runtime
func Detect() Platform {
	switch runtime.GOOS {
	case "darwin":
		return PlatformDarwin
	case "linux":
		return PlatformLinux
	case "windows":
		return PlatformWindows
	default:
		return PlatformUnknown
	}
}

// IsSupported returns true if the platform is supported
func (p Platform) IsSupported() bool {
	return p == PlatformDarwin || p == PlatformLinux || p == PlatformWindows
}

// String returns the string representation of the platform
func (p Platform) String() string {
	return string(p)
}
