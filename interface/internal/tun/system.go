package tun

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/execabs"
)

// SystemManager handles system-level operations for TUN interfaces
type SystemManager struct{}

// NewSystemManager creates a new system manager
func NewSystemManager() *SystemManager {
	return &SystemManager{}
}

// ConfigureInterface configures a TUN interface with IP address, netmask, and MTU
func (systemManager *SystemManager) ConfigureInterface(name string, addr, netmask string, mtu int) error {
	// Set IP address and netmask
	if err := systemManager.setIPAddress(name, addr, netmask); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}

	// Set MTU
	if err := systemManager.setMTU(name, mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Bring interface up
	if err := systemManager.bringUp(name); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// getDefaultGateway gets the current default gateway
func (systemManager *SystemManager) getDefaultGateway() (string, error) {
	cmd := execabs.Command("route", "-n", "get", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("    [SYSTEM] failed to get default gateway: %s, %w", string(output), err)
		return "", err
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

	log.Fatalln("    [SYSTEM] could not find default gateway in route output")
	return "", err
}

// calculateBroadcast calculates the broadcast address from IP and netmask
func (systemManager *SystemManager) calculateBroadcast(ip, netmask string) string {
	// Parse IP and netmask
	ipParts := strings.Split(ip, ".")
	netmaskParts := strings.Split(netmask, ".")

	if len(ipParts) != 4 || len(netmaskParts) != 4 {
		return "10.0.0.255" // Fallback
	}

	// Calculate broadcast address via binary wizardry
	broadcast := make([]string, 4)
	for i := 0; i < 4; i++ {
		ipByte := 0
		netmaskByte := 0
		fmt.Sscanf(ipParts[i], "%d", &ipByte)
		fmt.Sscanf(netmaskParts[i], "%d", &netmaskByte)

		// Broadcast = IP | (~netmask)
		broadcastByte := ipByte | (255 ^ netmaskByte)
		broadcast[i] = fmt.Sprintf("%d", broadcastByte)
	}

	return strings.Join(broadcast, ".")
}

// setIPAddress sets the IP address and netmask for the interface
func (systemManager *SystemManager) setIPAddress(name, addr, netmask string) error {
	var cmd *exec.Cmd
	var args []string

	// Handle platform-specific ifconfig syntax
	if runtime.GOOS == "darwin" {
		// macOS: bring interface up first, then set IP with broadcast
		upCmd := exec.Command("ifconfig", name, "up")
		upCmd.CombinedOutput() // Ignore errors, interface might already be up

		// Calculate broadcast address dynamically
		broadcast := systemManager.calculateBroadcast(addr, netmask)

		// Use broadcast to make it non-P2P
		args = []string{name, "inet", addr, "netmask", netmask, "broadcast", broadcast}
		cmd = exec.Command("ifconfig", args...)
	} else {
		// Linux and other Unix systems
		args = []string{name, addr, "netmask", netmask}
		cmd = exec.Command("ifconfig", args...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig failed: %s, %w", string(output), err)
	}
	return nil
}

// setMTU sets the MTU for the interface
func (systemManager *SystemManager) setMTU(name string, mtu int) error {
	cmd := exec.Command("ifconfig", name, "mtu", fmt.Sprintf("%d", mtu))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig mtu failed: %s, %w", string(output), err)
	}
	return nil
}

// bringUp brings the interface up
func (systemManager *SystemManager) bringUp(name string) error {
	cmd := exec.Command("ifconfig", name, "up")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig up failed: %s, %w", string(output), err)
	}
	return nil
}

// bringDown brings the interface down
func (systemManager *SystemManager) bringDown(name string) error {
	cmd := exec.Command("ifconfig", name, "down")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig down failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteInterface removes the interface
func (systemManager *SystemManager) DeleteInterface(name string) error {
	// First bring it down
	if err := systemManager.bringDown(name); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	// Then delete it (this might require root privileges)
	cmd := exec.Command("ifconfig", name, "destroy")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// On some systems, the interface is automatically removed when closed
		// So we'll just log this as a warning and return nil
		// This prevents the error from propagating up and causing issues
		log.Printf("    [SYSTEM] Warning: could not destroy interface %s: %s", name, string(output))
		return nil // Don't treat this as a fatal error
	}
	return nil
}

// GetInterfaceStatus returns the status of an interface
func (systemManager *SystemManager) GetInterfaceStatus(name string) (map[string]string, error) {
	cmd := exec.Command("ifconfig", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface status: %w", err)
	}

	// Parse the ifconfig output
	return systemManager.parseIfconfigOutput(string(output)), nil
}

// parseIfconfigOutput parses the output of ifconfig command
func (systemManager *SystemManager) parseIfconfigOutput(output string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			// Extract IP address
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				result["ip"] = parts[1]
			}
		} else if strings.HasPrefix(line, "netmask ") {
			// Extract netmask
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				result["netmask"] = parts[1]
			}
		} else if strings.HasPrefix(line, "mtu ") {
			// Extract MTU
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				result["mtu"] = parts[1]
			}
		} else if strings.Contains(line, "UP") {
			result["status"] = "UP"
		} else if strings.Contains(line, "DOWN") {
			result["status"] = "DOWN"
		}
	}

	return result
}

// AddRoute adds a route for the interface
func (systemManager *SystemManager) AddRoute(interfaceName, destination, gateway string) error {
	args := []string{"add", destination}
	if gateway != "" {
		args = append(args, gateway)
	}
	args = append(args, "-interface", interfaceName)

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add failed: %s, %w", string(output), err)
	}
	return nil
}

// DeleteRoute removes a route for the interface
func (systemManager *SystemManager) DeleteRoute(interfaceName, destination, gateway string) error {
	args := []string{"delete", destination}
	if gateway != "" {
		args = append(args, gateway)
	}
	args = append(args, "-interface", interfaceName)

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete failed: %s, %w", string(output), err)
	}
	return nil
}
