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
)

// InterfaceManager handles TUN/TAP interface operations
type InterfaceManager struct {
	iface         *water.Interface
	config        *water.Config
	name          string
	mtu           int
	address       net.IP
	netmask       net.IP
	systemManager *SystemManager

	// Cleanup management
	stopChan     chan struct{}
	wg           sync.WaitGroup
	controlMutex sync.Mutex
	isRunning    bool
}

// NewInterfaceManager creates a new TUN interface manager
func NewInterfaceManager(name string, mtu int, addr, netmask net.IP) *InterfaceManager {
	// Use a custom prefix to avoid conflicts with system interfaces
	if name == "" {
		name = "utun9" // Default name with custom prefix
	}

	return &InterfaceManager{
		name:          name,
		mtu:           mtu,
		address:       addr,
		netmask:       netmask,
		systemManager: NewSystemManager(),
		stopChan:      make(chan struct{}),
	}
}

// Create creates a new TUN interface
func (interfaceManager *InterfaceManager) Create() error {
	interfaceManager.controlMutex.Lock()
	defer interfaceManager.controlMutex.Unlock()

	// Configure the TUN interface
	interfaceManager.config = &water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: interfaceManager.name,
		},
	}

	// Create the interface
	iface, err := water.New(*interfaceManager.config)
	if err != nil {
		log.Fatalf("    [MANAGER] failed to create TUN interface: %w", err)
		return err
	}

	interfaceManager.iface = iface

	// Configure the interface
	if err := interfaceManager.configure(); err != nil {
		interfaceManager.iface.Close()
		log.Fatalf("    [MANAGER] failed to configure interface: %w", err)
		return err
	}

	// Set up signal handling for cleanup
	interfaceManager.setupSignalHandling()

	return nil
}

// InterceptAllTraffic sets up routing to intercept all internet traffic
// TODO: refactor
func (interfaceManager *InterfaceManager) InterceptAllTraffic() error {
	log.Fatalf("    [MANAGER] `InterceptAllTraffic` is not implemented (yet)")
	return nil
}

// CreateRouteFor10Subnet creates a route for the 10.0.0.0/24 subnet through the TUN interface
func (interfaceManager *InterfaceManager) CreateRouteFor10Subnet() error {
	// Get the actual interface name from the water interface
	actualName := interfaceManager.iface.Name()
	log.Printf("    [MANAGER] Creating route for 10.0.0.0/24 subnet through interface %s (actual: %s)", interfaceManager.name, actualName)

	// Get the default gateway
	gateway, err := interfaceManager.systemManager.getDefaultGateway()
	if err != nil {
		log.Fatalf("    [MANAGER] failed to get default gateway: %w", err)
		return err
	}

	// Try to add the route using the actual interface name
	if err := interfaceManager.systemManager.AddRoute(actualName, "10.0.0.0/24", gateway); err != nil {
		// If that fails, try without gateway (some systems don't need it for interface routes)
		log.Printf("    [MANAGER] First route attempt failed, trying without gateway: %v", err)
		if err := interfaceManager.systemManager.AddRoute(actualName, "10.0.0.0/24", ""); err != nil {
			log.Fatalf("    [MANAGER] failed to add route for 10.0.0.0/24: %w", err)
			return err
		}
	}

	log.Printf("    [MANAGER] Successfully created route for 10.0.0.0/24 subnet through %s", actualName)
	return nil
}

// RemoveRouteFor10Subnet removes the route for the 10.0.0.0/24 subnet
func (interfaceManager *InterfaceManager) RemoveRouteFor10Subnet() error {
	// Get the actual interface name from the water interface
	actualName := interfaceManager.iface.Name()
	log.Printf("    [MANAGER] Removing route for 10.0.0.0/24 subnet from interface %s", actualName)

	// Try to delete the route using the system manager
	if err := interfaceManager.systemManager.DeleteRoute(actualName, "10.0.0.0/24", ""); err != nil {
		// If that fails, try with gateway
		log.Printf("    [MANAGER] First delete attempt failed, trying with gateway: %v", err)
		gateway, gatewayErr := interfaceManager.systemManager.getDefaultGateway()
		if gatewayErr == nil {
			if err := interfaceManager.systemManager.DeleteRoute(actualName, "10.0.0.0/24", gateway); err != nil {
				log.Printf("    [MANAGER] Warning: could not delete route for 10.0.0.0/24: %v", err)
				return nil // Don't treat route deletion failure as fatal
			}
		} else {
			log.Printf("    [MANAGER] Warning: could not delete route for 10.0.0.0/24: %v", err)
			return nil // Don't treat route deletion failure as fatal
		}
	}

	log.Printf("    [MANAGER] Successfully removed route for 10.0.0.0/24 subnet")
	return nil
}

// setupSignalHandling sets up signal handlers for graceful shutdown
func (interfaceManager *InterfaceManager) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		sig := <-sigChan
		log.Printf("    [MANAGER] Received signal %v, shutting down gracefully...", sig)
		interfaceManager.Cleanup()
		os.Exit(0)
	}()
}

// configure sets up the interface with IP address, netmask, and MTU
func (interfaceManager *InterfaceManager) configure() error {
	// Configure the interface using system commands
	if err := interfaceManager.systemManager.ConfigureInterface(
		interfaceManager.name,
		interfaceManager.address.String(),
		interfaceManager.netmask.String(),
		interfaceManager.mtu); err != nil {

		log.Fatalf("    [MANAGER] failed to configure interface: %w", err)

		return err
	}

	log.Printf(
		"Configured interface %s with IP %s, MTU %d",
		interfaceManager.name,
		interfaceManager.address.String(),
		interfaceManager.mtu,
	)
	return nil
}

// Start begins packet processing
func (interfaceManager *InterfaceManager) Start() error {
	interfaceManager.controlMutex.Lock()
	defer interfaceManager.controlMutex.Unlock()

	if interfaceManager.iface == nil {
		return fmt.Errorf("interface not created")
	}

	if interfaceManager.isRunning {
		return fmt.Errorf("interface is already running")
	}

	log.Printf("    [MANAGER] Starting packet processing on interface %s", interfaceManager.name)

	// Create route for 10.0.0.0/24 subnet
	if err := interfaceManager.CreateRouteFor10Subnet(); err != nil {
		return fmt.Errorf("failed to create route for 10 subnet: %w", err)
	}

	// Start packet processing in a goroutine
	interfaceManager.wg.Add(1)
	interfaceManager.isRunning = true
	interfaceManager.stopChan = make(chan struct{})
	go interfaceManager.processPackets()

	return nil
}

// processPackets handles incoming and outgoing packets
func (interfaceManager *InterfaceManager) processPackets() {
	defer interfaceManager.wg.Done()

	buffer := make([]byte, 2048)

	for {
		select {
		case <-interfaceManager.stopChan:
			log.Printf("    [MANAGER] Stopping packet processing on interface %s", interfaceManager.name)
			return
		default:
			// Continue processing
		}

		// Check if interface is still valid
		if interfaceManager.iface == nil {
			log.Printf("    [MANAGER] Interface is nil, stopping packet processing")
			return
		}

		// Use a timeout to make the read interruptible
		// This allows the goroutine to exit when stopChan is closed
		done := make(chan struct{})
		var n int
		var err error

		go func() {
			n, err = interfaceManager.iface.Read(buffer)
			close(done)
		}()

		select {
		case <-done:
			// Read completed, process the packet
		case <-interfaceManager.stopChan:
			log.Printf("    [MANAGER] Stopping packet processing on interface %s", interfaceManager.name)
			return
		}

		if err != nil {
			if err == io.EOF {
				log.Println("    [MANAGER] Interface closed")
				break
			}
			// Check if the error is due to the interface being closed
			if strings.Contains(err.Error(), "file already closed") ||
				strings.Contains(err.Error(), "bad file descriptor") {
				log.Printf("    [MANAGER] Interface was closed, stopping packet processing")
				break
			}
			log.Printf("    [MANAGER] Error reading from interface: %v", err)
			continue
		}

		// Log packet info but don't echo back to prevent routing loops
		if n > 0 {
			interfaceManager.logPacketInfo(buffer[:n])
		}
	}
}

// logPacketInfo logs packet information without processing
func (interfaceManager *InterfaceManager) logPacketInfo(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Parse IP header
	version := packet[0] >> 4
	if version == 4 {
		interfaceManager.logIPv4Packet(packet)
	} else if version == 6 {
		interfaceManager.logIPv6Packet(packet)
	}
}

// logIPv4Packet logs IPv4 packet information
func (interfaceManager *InterfaceManager) logIPv4Packet(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Extract source and destination IPs
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	protocol := packet[9]

	// Log packet information with protocol details
	protocolName := getProtocolName(protocol)
	log.Printf("    [MANAGER] [PACKET] IPv4: %s -> %s (%s)", srcIP, dstIP, protocolName)
}

// logIPv6Packet logs IPv6 packet information
func (interfaceManager *InterfaceManager) logIPv6Packet(packet []byte) {
	if len(packet) < 40 {
		return
	}

	// Extract source and destination IPs
	srcIP := net.IP(packet[8:24])
	dstIP := net.IP(packet[24:40])
	nextHeader := packet[6]

	// Log packet information with protocol details
	protocolName := getProtocolName(nextHeader)
	log.Printf("    [MANAGER] [PACKET] IPv6: %s -> %s (%s)", srcIP, dstIP, protocolName)
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
func (interfaceManager *InterfaceManager) Stop() error {
	interfaceManager.controlMutex.Lock()
	defer interfaceManager.controlMutex.Unlock()

	if !interfaceManager.isRunning {
		return fmt.Errorf("interface is not running")
	}

	log.Printf("    [MANAGER] Stopping packet processing on interface %s", interfaceManager.name)

	// Remove route for 10.0.0.0/24 subnet
	if err := interfaceManager.RemoveRouteFor10Subnet(); err != nil {
		log.Printf("    [MANAGER] Warning: failed to remove route for 10 subnet: %v", err)
	}

	// Signal the packet processing goroutine to stop
	close(interfaceManager.stopChan)

	// Wait for the goroutine to finish
	interfaceManager.wg.Wait()

	interfaceManager.isRunning = false
	return nil
}

// Close closes the interface and cleans up resources
func (interfaceManager *InterfaceManager) Close() error {
	// It takes hold of controlMutex so we run it before we try to lock
	if interfaceManager.isRunning {
		interfaceManager.Stop()
	}

	interfaceManager.controlMutex.Lock()
	defer interfaceManager.controlMutex.Unlock()

	log.Printf("    [MANAGER] Closing interface %s", interfaceManager.name)

	// Close the interface
	if interfaceManager.iface != nil {
		if err := interfaceManager.iface.Close(); err != nil {
			log.Printf("    [MANAGER] Error closing interface: %v", err)
		}
		interfaceManager.iface = nil
	}

	return nil
}

// Cleanup performs complete cleanup including system-level cleanup
func (interfaceManager *InterfaceManager) Cleanup() error {
	log.Printf("    [MANAGER] Performing complete cleanup for interface %s", interfaceManager.name)

	// Close the interface
	if err := interfaceManager.Close(); err != nil {
		log.Printf("    [MANAGER] Error during interface close: %v", err)
	}

	// Clean up system resources
	if err := interfaceManager.systemManager.DeleteInterface(interfaceManager.name); err != nil {
		log.Printf("    [MANAGER] Warning: failed to delete system interface: %v", err)
	}

	log.Printf("    [MANAGER] Cleanup completed for interface %s", interfaceManager.name)
	return nil
}

// GetStatus returns the current status of the interface
func (interfaceManager *InterfaceManager) GetStatus() map[string]interface{} {
	interfaceManager.controlMutex.Lock()
	defer interfaceManager.controlMutex.Unlock()

	status := map[string]interface{}{
		"name":    interfaceManager.name,
		"mtu":     interfaceManager.mtu,
		"address": interfaceManager.address.String(),
		"netmask": interfaceManager.netmask.String(),
		"up":      interfaceManager.iface != nil,
		"running": interfaceManager.isRunning,
	}

	if interfaceManager.iface != nil {
		// Get system interface details
		iface, err := net.InterfaceByName(interfaceManager.name)
		if err == nil {
			status["index"] = iface.Index
			status["flags"] = iface.Flags
			status["hardware_addr"] = iface.HardwareAddr.String()
		}
	}

	return status
}
