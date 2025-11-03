//go:build linux
// +build linux

package linux

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// SystemManager handles Linux-specific system operations for TUN interfaces
type SystemManager struct{}

// NewSystemManager creates a new Linux system manager
func NewSystemManager() *SystemManager {
	return &SystemManager{}
}

// ConfigureInterface configures a TUN interface with IP address, netmask, and MTU
func (sm *SystemManager) ConfigureInterface(name string, addr, netmask string, mtu int) error {
	// Set IP address and netmask
	args := []string{name, addr, "netmask", netmask}
	cmd := exec.Command("ifconfig", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig failed: %s, %w", string(output), err)
	}

	// Set MTU
	if err := sm.setMTU(name, mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Bring interface up
	if err := sm.bringUp(name); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// GetDefaultGateway gets the current default gateway (Linux)
func (sm *SystemManager) GetDefaultGateway() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get default gateway: %s, %w", string(output), err)
	}

	// Parse output: default via 192.168.1.1 dev eth0
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "default" && fields[1] == "via" {
			return fields[2], nil
		}
	}

	return "", fmt.Errorf("could not find default gateway in route output")
}

// setMTU sets the MTU for the interface
func (sm *SystemManager) setMTU(name string, mtu int) error {
	cmd := exec.Command("ifconfig", name, "mtu", fmt.Sprintf("%d", mtu))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig mtu failed: %s, %w", string(output), err)
	}
	return nil
}

// bringUp brings the interface up
func (sm *SystemManager) bringUp(name string) error {
	cmd := exec.Command("ifconfig", name, "up")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig up failed: %s, %w", string(output), err)
	}
	return nil
}

// AddRoute adds a route for the interface (Linux)
func (sm *SystemManager) AddRoute(interfaceName, destination, gateway string) error {
	// Linux uses 'ip route add' command
	args := []string{"route", "add", destination, "dev", interfaceName}
	if gateway != "" {
		args = []string{"route", "add", destination, "via", gateway, "dev", interfaceName}
	}

	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route add failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteRoute removes a route for the interface (Linux)
func (sm *SystemManager) DeleteRoute(interfaceName, destination, gateway string) error {
	args := []string{"route", "delete", destination, "dev", interfaceName}
	if gateway != "" {
		args = []string{"route", "delete", destination, "via", gateway, "dev", interfaceName}
	}

	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route delete failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteInterface removes the interface (Linux)
func (sm *SystemManager) DeleteInterface(name string) error {
	// Bring it down first
	cmd := exec.Command("ifconfig", name, "down")
	cmd.CombinedOutput() // Ignore errors

	// On Linux, TUN interfaces are usually managed by the kernel and removed automatically
	// when closed, but we can try to use ip link delete if needed
	cmd = exec.Command("ip", "link", "delete", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[SYSTEM] Warning: could not delete interface %s: %s", name, string(output))
		return nil // Don't treat as fatal
	}
	return nil
}
