//go:build windows
// +build windows

package windows

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// SystemManager handles Windows-specific system operations for TUN interfaces
type SystemManager struct{}

// NewSystemManager creates a new Windows system manager
func NewSystemManager() *SystemManager {
	return &SystemManager{}
}

// ConfigureInterface configures a TUN interface with IP address, netmask, and MTU
func (sm *SystemManager) ConfigureInterface(name string, addr, netmask string, mtu int) error {
	// Windows uses netsh for interface configuration
	// Calculate netmask prefix length
	_, err := sm.netmaskToPrefixLength(netmask)
	if err != nil {
		return fmt.Errorf("invalid netmask: %w", err)
	}

	// Set IP address using netsh
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", name), "static", addr, netmask)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address failed: %s, %w", string(output), err)
	}

	// Set MTU (Windows uses netsh interface ipv4 set subinterface)
	cmd = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("\"%s\"", name), fmt.Sprintf("mtu=%d", mtu), "store=persistent")
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("[SYSTEM] Warning: could not set MTU: %s", string(output))
		// Continue, MTU setting might not be critical
	}

	return nil
}

// GetDefaultGateway gets the current default gateway (Windows)
func (sm *SystemManager) GetDefaultGateway() (string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get default gateway: %s, %w", string(output), err)
	}

	// Parse output - Windows route print format
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// Look for default route (0.0.0.0 with mask 0.0.0.0)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			if len(fields) >= 3 {
				return fields[2], nil
			}
		}
	}

	return "", fmt.Errorf("could not find default gateway in route output")
}

// netmaskToPrefixLength converts netmask to prefix length
func (sm *SystemManager) netmaskToPrefixLength(netmask string) (int, error) {
	parts := strings.Split(netmask, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid netmask format")
	}

	prefixLen := 0
	for _, part := range parts {
		var octet int
		fmt.Sscanf(part, "%d", &octet)
		for octet > 0 {
			prefixLen++
			octet <<= 1
		}
	}
	return prefixLen, nil
}

// AddRoute adds a route for the interface (Windows)
func (sm *SystemManager) AddRoute(interfaceName, destination, gateway string) error {
	args := []string{"route", "add", destination}
	if gateway != "" {
		args = append(args, gateway)
	}
	args = append(args, "if", interfaceName)

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteRoute removes a route for the interface (Windows)
func (sm *SystemManager) DeleteRoute(interfaceName, destination, gateway string) error {
	args := []string{"route", "delete", destination}
	if gateway != "" {
		args = append(args, gateway)
	}

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteInterface removes the interface (Windows)
func (sm *SystemManager) DeleteInterface(name string) error {
	// On Windows, TUN interfaces are typically managed by the driver
	// Use netsh to disable the interface
	cmd := exec.Command("netsh", "interface", "set", "interface", fmt.Sprintf("name=%s", name), "admin=disable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[SYSTEM] Warning: could not disable interface %s: %s", name, string(output))
		return nil // Don't treat as fatal
	}
	return nil
}
