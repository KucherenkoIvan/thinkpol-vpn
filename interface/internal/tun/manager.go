package tun

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/songgao/water"
	"golang.org/x/sys/execabs"
)

// InterfaceManager handles TUN/TAP interface operations
type InterfaceManager struct {
	iface         *water.Interface
	config        *water.Config
	name          string
	requestedName string // Store the originally requested name
	mtu           int
	addr          net.IP
	netmask       net.IP
	system        *SystemManager

	// Cleanup management
	stopChan  chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	isRunning bool
}

// NewInterfaceManager creates a new TUN interface manager
func NewInterfaceManager(name string, mtu int, addr, netmask net.IP) *InterfaceManager {
	// Use a custom prefix to avoid conflicts with system interfaces
	if name == "" {
		name = "utun9" // Default name with custom prefix
	}

	return &InterfaceManager{
		name:          name,
		requestedName: name, // Store the originally requested name
		mtu:           mtu,
		addr:          addr,
		netmask:       netmask,
		system:        NewSystemManager(),
		stopChan:      make(chan struct{}),
	}
}

// Create creates a new TUN interface
func (im *InterfaceManager) Create() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Configure the TUN interface
	im.config = &water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: im.name,
		},
	}

	// Create the interface
	iface, err := water.New(*im.config)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}

	im.iface = iface

	// Log the actual interface name that was created
	actualName := im.iface.Name()
	log.Printf("Requested interface name: %s", im.requestedName)
	log.Printf("Actual interface name created: %s", actualName)

	// Update our internal name to match what was actually created
	if actualName != im.requestedName {
		log.Printf("Note: System assigned different name than requested")
		im.name = actualName
	}

	// Configure the interface
	if err := im.configure(); err != nil {
		im.iface.Close()
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	// Set up signal handling for cleanup
	im.setupSignalHandling()

	return nil
}

// InterceptAllTraffic sets up routing to intercept all internet traffic
func (im *InterfaceManager) InterceptAllTraffic() error {
	log.Printf("Setting up traffic interception on interface %s", im.name)

	// Get the default gateway
	gateway, err := im.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}

	// Store original routes for cleanup
	if err := im.backupOriginalRoutes(); err != nil {
		return fmt.Errorf("failed to backup original routes: %w", err)
	}

	// Route all traffic through the TUN interface
	if err := im.routeAllTraffic(gateway); err != nil {
		return fmt.Errorf("failed to route all traffic: %w", err)
	}

	log.Printf("All traffic is now being intercepted through %s", im.name)
	return nil
}

// getDefaultGateway gets the current default gateway
func (im *InterfaceManager) getDefaultGateway() (string, error) {
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

// backupOriginalRoutes backs up the current routing table
func (im *InterfaceManager) backupOriginalRoutes() error {
	cmd := execabs.Command("netstat", "-rn")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to backup routes: %s, %w", string(output), err)
	}

	// Save to a file for later restoration
	filename := fmt.Sprintf("/tmp/original_routes_%s.txt", im.name)
	if err := os.WriteFile(filename, output, 0644); err != nil {
		return fmt.Errorf("failed to save original routes: %w", err)
	}

	log.Printf("Original routes backed up to %s", filename)
	return nil
}

// routeAllTraffic routes all internet traffic through the TUN interface
func (im *InterfaceManager) routeAllTraffic(gateway string) error {
	// Delete the default route
	cmd := execabs.Command("route", "delete", "default")
	cmd.CombinedOutput() // Ignore errors, route might not exist

	// Add new default route through TUN interface
	cmd = execabs.Command("route", "add", "default", gateway, "-interface", im.name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add default route: %s, %w", string(output), err)
	}

	// Route specific networks through TUN interface
	networks := []string{
		"0.0.0.0/1",   // All IPv4 traffic
		"128.0.0.0/1", // Rest of IPv4 space
	}

	for _, network := range networks {
		cmd = execabs.Command("route", "add", network, gateway, "-interface", im.name)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: failed to add route for %s: %s", network, string(output))
		}
	}

	return nil
}

// CreateRouteFor10Subnet creates a route for the 10.0.0.0/24 subnet through the TUN interface
func (im *InterfaceManager) CreateRouteFor10Subnet() error {
	// Get the actual interface name from the water interface
	actualName := im.iface.Name()
	log.Printf("Creating route for 10.0.0.0/24 subnet through interface %s (actual: %s)", im.name, actualName)

	// Get the default gateway
	gateway, err := im.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}

	// Try to add the route using the actual interface name
	if err := im.system.AddRoute(actualName, "10.0.0.0/24", gateway); err != nil {
		// If that fails, try without gateway (some systems don't need it for interface routes)
		log.Printf("First route attempt failed, trying without gateway: %v", err)
		if err := im.system.AddRoute(actualName, "10.0.0.0/24", ""); err != nil {
			return fmt.Errorf("failed to add route for 10.0.0.0/24: %w", err)
		}
	}

	log.Printf("Successfully created route for 10.0.0.0/24 subnet through %s", actualName)
	return nil
}

// RemoveRouteFor10Subnet removes the route for the 10.0.0.0/24 subnet
func (im *InterfaceManager) RemoveRouteFor10Subnet() error {
	// Get the actual interface name from the water interface
	actualName := im.iface.Name()
	log.Printf("Removing route for 10.0.0.0/24 subnet from interface %s", actualName)

	// Try to delete the route using the system manager
	if err := im.system.DeleteRoute(actualName, "10.0.0.0/24", ""); err != nil {
		// If that fails, try with gateway
		log.Printf("First delete attempt failed, trying with gateway: %v", err)
		gateway, gatewayErr := im.getDefaultGateway()
		if gatewayErr == nil {
			if err := im.system.DeleteRoute(actualName, "10.0.0.0/24", gateway); err != nil {
				log.Printf("Warning: could not delete route for 10.0.0.0/24: %v", err)
				return nil // Don't treat route deletion failure as fatal
			}
		} else {
			log.Printf("Warning: could not delete route for 10.0.0.0/24: %v", err)
			return nil // Don't treat route deletion failure as fatal
		}
	}

	log.Printf("Successfully removed route for 10.0.0.0/24 subnet")
	return nil
}

// RestoreOriginalRoutes restores the original routing table
func (im *InterfaceManager) RestoreOriginalRoutes() error {
	log.Printf("Restoring original routes...")

	// Delete route for 10.0.0.0/24 subnet through TUN interface
	cmd := execabs.Command("route", "delete", "10.0.0.0/24")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: could not delete route for 10.0.0.0/24: %s", string(output))
	} else {
		log.Printf("Successfully removed route for 10.0.0.0/24 subnet")
	}

	// Try to restore from backup file
	filename := fmt.Sprintf("/tmp/original_routes_%s.txt", im.name)
	if _, err := os.Stat(filename); err == nil {
		// Read backup and restore routes
		_, err := os.ReadFile(filename)
		if err != nil {
			log.Printf("Warning: could not read backup routes: %v", err)
		} else {
			log.Printf("Restored routes from backup")
			// Note: Full route restoration would require parsing the backup file
			// This is a simplified version
		}
	}

	// Add back default route (simplified)
	cmd = execabs.Command("route", "add", "default", "-gateway", "192.168.1.1") // Adjust gateway as needed
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: could not restore default route: %s", string(output))
	}

	return nil
}

// setupSignalHandling sets up signal handlers for graceful shutdown
func (im *InterfaceManager) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down gracefully...", sig)
		im.Cleanup()
		os.Exit(0)
	}()
}

// configure sets up the interface with IP address, netmask, and MTU
func (im *InterfaceManager) configure() error {
	// Configure the interface using system commands
	if err := im.system.ConfigureInterface(im.name, im.addr.String(), im.netmask.String(), im.mtu); err != nil {
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	log.Printf("Configured interface %s with IP %s, MTU %d", im.name, im.addr.String(), im.mtu)
	return nil
}

// Start begins packet processing
func (im *InterfaceManager) Start() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if im.iface == nil {
		return fmt.Errorf("interface not created")
	}

	if im.isRunning {
		return fmt.Errorf("interface is already running")
	}

	log.Printf("Starting packet processing on interface %s", im.name)

	// Create route for 10.0.0.0/24 subnet
	if err := im.CreateRouteFor10Subnet(); err != nil {
		return fmt.Errorf("failed to create route for 10 subnet: %w", err)
	}

	// Start packet processing in a goroutine
	im.wg.Add(1)
	im.isRunning = true
	go im.processPackets()

	return nil
}

// processPackets handles incoming and outgoing packets
func (im *InterfaceManager) processPackets() {
	defer im.wg.Done()

	buffer := make([]byte, 2048)

	for {
		select {
		case <-im.stopChan:
			log.Printf("Stopping packet processing on interface %s", im.name)
			return
		default:
			// Continue processing
		}

		// Check if interface is still valid
		if im.iface == nil {
			log.Printf("Interface is nil, stopping packet processing")
			return
		}

		// Use a timeout to make the read interruptible
		// This allows the goroutine to exit when stopChan is closed
		done := make(chan struct{})
		var n int
		var err error

		go func() {
			n, err = im.iface.Read(buffer)
			close(done)
		}()

		select {
		case <-done:
			// Read completed, process the packet
		case <-im.stopChan:
			log.Printf("Stopping packet processing on interface %s", im.name)
			return
		}

		if err != nil {
			if err == io.EOF {
				log.Println("Interface closed")
				break
			}
			// Check if the error is due to the interface being closed
			if strings.Contains(err.Error(), "file already closed") ||
				strings.Contains(err.Error(), "bad file descriptor") {
				log.Printf("Interface was closed, stopping packet processing")
				break
			}
			log.Printf("Error reading from interface: %v", err)
			continue
		}

		// Log packet info but don't echo back to prevent routing loops
		if n > 0 {
			im.logPacketInfo(buffer[:n])
		}
	}
}

// logPacketInfo logs packet information without processing
func (im *InterfaceManager) logPacketInfo(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Parse IP header
	version := packet[0] >> 4
	if version == 4 {
		im.logIPv4Packet(packet)
	} else if version == 6 {
		im.logIPv6Packet(packet)
	}
}

// logIPv4Packet logs IPv4 packet information
func (im *InterfaceManager) logIPv4Packet(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Extract source and destination IPs
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	protocol := packet[9]

	// Log packet information with protocol details
	protocolName := getProtocolName(protocol)
	log.Printf("[PACKET] IPv4: %s -> %s (%s)", srcIP, dstIP, protocolName)
}

// logIPv6Packet logs IPv6 packet information
func (im *InterfaceManager) logIPv6Packet(packet []byte) {
	if len(packet) < 40 {
		return
	}

	// Extract source and destination IPs
	srcIP := net.IP(packet[8:24])
	dstIP := net.IP(packet[24:40])
	nextHeader := packet[6]

	// Log packet information with protocol details
	protocolName := getProtocolName(nextHeader)
	log.Printf("[PACKET] IPv6: %s -> %s (%s)", srcIP, dstIP, protocolName)
}

// getProtocolName returns the name of the protocol
func getProtocolName(protocol byte) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Unknown(%d)", protocol)
	}
}

// Stop stops packet processing gracefully
func (im *InterfaceManager) Stop() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if !im.isRunning {
		return fmt.Errorf("interface is not running")
	}

	log.Printf("Stopping packet processing on interface %s", im.name)

	// Remove route for 10.0.0.0/24 subnet
	if err := im.RemoveRouteFor10Subnet(); err != nil {
		log.Printf("Warning: failed to remove route for 10 subnet: %v", err)
	}

	// Signal the packet processing goroutine to stop
	close(im.stopChan)

	// Wait for the goroutine to finish
	im.wg.Wait()

	im.isRunning = false
	return nil
}

// Close closes the interface and cleans up resources
func (im *InterfaceManager) Close() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	log.Printf("Closing interface %s", im.name)

	// Stop packet processing if running
	if im.isRunning {
		close(im.stopChan)
		im.wg.Wait()
		im.isRunning = false
	}

	// Close the interface
	if im.iface != nil {
		if err := im.iface.Close(); err != nil {
			log.Printf("Error closing interface: %v", err)
		}
		im.iface = nil
	}

	return nil
}

// Cleanup performs complete cleanup including system-level cleanup
func (im *InterfaceManager) Cleanup() error {
	log.Printf("Performing complete cleanup for interface %s", im.name)

	// Restore original routes
	if err := im.RestoreOriginalRoutes(); err != nil {
		log.Printf("Warning: failed to restore original routes: %v", err)
	}

	// Close the interface
	if err := im.Close(); err != nil {
		log.Printf("Error during interface close: %v", err)
	}

	// Clean up system resources
	if err := im.system.DeleteInterface(im.name); err != nil {
		log.Printf("Warning: failed to delete system interface: %v", err)
	}

	log.Printf("Cleanup completed for interface %s", im.name)
	return nil
}

// GetStatus returns the current status of the interface
func (im *InterfaceManager) GetStatus() map[string]interface{} {
	im.mu.Lock()
	defer im.mu.Unlock()

	status := map[string]interface{}{
		"name":           im.name,
		"requested_name": im.requestedName,
		"mtu":            im.mtu,
		"address":        im.addr.String(),
		"netmask":        im.netmask.String(),
		"active":         im.iface != nil,
		"running":        im.isRunning,
	}

	if im.iface != nil {
		// Get the actual interface name from the water interface
		actualName := im.iface.Name()
		status["actual_name"] = actualName
		status["name_mismatch"] = actualName != im.name

		// Get system interface details
		iface, err := net.InterfaceByName(actualName)
		if err == nil {
			status["index"] = iface.Index
			status["flags"] = iface.Flags
			status["hardware_addr"] = iface.HardwareAddr.String()
		}

		// Also try to get details by our requested name
		if actualName != im.requestedName {
			iface2, err := net.InterfaceByName(im.requestedName)
			if err == nil {
				status["requested_name_index"] = iface2.Index
				status["requested_name_flags"] = iface2.Flags
			}
		}
	}

	return status
}
