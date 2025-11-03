//go:build darwin
// +build darwin

package darwin

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"golang.org/x/sys/execabs"
)

// SystemManager handles macOS-specific system operations for TUN interfaces
type SystemManager struct{}

// NewSystemManager creates a new macOS system manager
func NewSystemManager() *SystemManager {
	return &SystemManager{}
}

// ConfigureInterface configures a TUN interface with IP address, netmask, and MTU
func (sm *SystemManager) ConfigureInterface(name string, addr, netmask string, mtu int) error {
	// Bring interface up first
	upCmd := exec.Command("ifconfig", name, "up")
	upCmd.CombinedOutput() // Ignore errors, interface might already be up

	// Calculate broadcast address
	broadcast := sm.calculateBroadcast(addr, netmask)

	// Set IP address with broadcast (macOS specific)
	args := []string{name, "inet", addr, "netmask", netmask, "broadcast", broadcast}
	cmd := exec.Command("ifconfig", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig failed: %s, %w", string(output), err)
	}

	// Set MTU
	if err := sm.setMTU(name, mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}

// GetDefaultGateway gets the current default gateway (macOS)
func (sm *SystemManager) GetDefaultGateway() (string, error) {
	cmd := execabs.Command("route", "-n", "get", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get default gateway: %s, %w", string(output), err)
	}

	// Parse the output to find the gateway
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("could not find default gateway in route output")
}

// calculateBroadcast calculates the broadcast address from IP and netmask
func (sm *SystemManager) calculateBroadcast(ip, netmask string) string {
	ipParts := strings.Split(ip, ".")
	netmaskParts := strings.Split(netmask, ".")

	if len(ipParts) != 4 || len(netmaskParts) != 4 {
		return "10.0.0.255" // Fallback
	}

	broadcast := make([]string, 4)
	for i := 0; i < 4; i++ {
		var ipByte, netmaskByte int
		fmt.Sscanf(ipParts[i], "%d", &ipByte)
		fmt.Sscanf(netmaskParts[i], "%d", &netmaskByte)

		// Broadcast = IP | (~netmask)
		broadcastByte := ipByte | (255 ^ netmaskByte)
		broadcast[i] = fmt.Sprintf("%d", broadcastByte)
	}

	return strings.Join(broadcast, ".")
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

// AddRoute adds a route for the interface (macOS)
func (sm *SystemManager) AddRoute(interfaceName, destination, gateway string) error {
	// macOS route syntax:
	//   route add <destination> -interface <interface>  (for interface routes)
	//   route add <destination> <gateway>              (for gateway routes)
	args := []string{"add", destination}

	// Interface routes: use -interface (ignore gateway parameter)
	// Gateway routes: use gateway IP (when interfaceName is empty)
	if interfaceName != "" {
		// Interface route - use -interface flag, ignore gateway
		args = append(args, "-interface", interfaceName)
	} else if gateway != "" {
		// Gateway route - use gateway IP
		args = append(args, gateway)
	}

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteRoute removes a route for the interface (macOS)
func (sm *SystemManager) DeleteRoute(interfaceName, destination, gateway string) error {
	args := []string{"delete", destination}

	// For interface routes, use -interface
	// For gateway routes, use gateway IP
	if interfaceName != "" {
		args = append(args, "-interface", interfaceName)
	} else if gateway != "" {
		args = append(args, gateway)
	}

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteInterface removes the interface (macOS)
func (sm *SystemManager) DeleteInterface(name string) error {
	// Bring it down first
	cmd := exec.Command("ifconfig", name, "down")
	cmd.CombinedOutput() // Ignore errors

	// Delete it
	cmd = exec.Command("ifconfig", name, "destroy")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[SYSTEM] Warning: could not destroy interface %s: %s", name, string(output))
		return nil // Don't treat as fatal
	}
	return nil
}
