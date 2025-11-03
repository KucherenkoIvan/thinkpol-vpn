package tun

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"thinkpol-vpn/internal/config"
	"thinkpol-vpn/internal/routing"

	"github.com/songgao/water"
)

// PacketHandler is a function that handles packets read from TUN
type PacketHandler func(data []byte, length int) error

// Manager handles TUN/TAP interface operations with platform-specific routing
type Manager struct {
	iface        *water.Interface
	config       *water.Config
	name         string
	mtu          int
	address      net.IP
	netmask      net.IP
	routingMgr   *routing.Manager
	interfaceCfg *config.InterfaceConfig

	// Packet handling
	upstreamHandler PacketHandler
	downstreamChan  chan []byte

	// Cleanup management
	stopChan     chan struct{}
	wg           sync.WaitGroup
	controlMutex sync.Mutex
	isRunning    bool
}

// NewManager creates a new TUN interface manager
func NewManager(interfaceCfg *config.InterfaceConfig) (*Manager, error) {
	if interfaceCfg == nil {
		return nil, fmt.Errorf("interface config is required")
	}

	ipAddress := net.ParseIP(interfaceCfg.Address)
	if ipAddress == nil {
		return nil, fmt.Errorf("invalid IP address: %s", interfaceCfg.Address)
	}

	ipMask := net.ParseIP(interfaceCfg.Netmask)
	if ipMask == nil {
		return nil, fmt.Errorf("invalid netmask: %s", interfaceCfg.Netmask)
	}

	// Create routing manager
	routingMgr, err := routing.NewManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create routing manager: %w", err)
	}

	return &Manager{
		name:           "", // Will be set after interface creation
		mtu:            interfaceCfg.MTU,
		address:        ipAddress,
		netmask:        ipMask,
		routingMgr:     routingMgr,
		interfaceCfg:   interfaceCfg,
		downstreamChan: make(chan []byte, 100), // Buffer for downstream packets
		stopChan:       make(chan struct{}),
	}, nil
}

// SetUpstreamHandler sets the handler for packets going upstream (TUN -> network)
func (m *Manager) SetUpstreamHandler(handler PacketHandler) {
	m.controlMutex.Lock()
	defer m.controlMutex.Unlock()
	m.upstreamHandler = handler
}

// Create creates a new TUN interface
func (m *Manager) Create() error {
	m.controlMutex.Lock()
	defer m.controlMutex.Unlock()

	// Configure the TUN interface using water library (cross-platform)
	// The OS will assign an interface name automatically
	m.config = &water.Config{
		DeviceType: water.TUN,
	}

	// Create the interface
	iface, err := water.New(*m.config)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}

	m.iface = iface

	// Get the actual interface name assigned by OS
	actualName := m.iface.Name()
	log.Printf("[TUN] Created TUN interface: %s", actualName)

	// Store the actual interface name
	m.name = actualName

	// Configure the interface using platform-specific system manager
	if err := m.routingMgr.ConfigureInterface(actualName, m.address.String(), m.netmask.String(), m.mtu); err != nil {
		m.iface.Close()
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	log.Printf("[TUN] Configured interface %s with IP %s, MTU %d", actualName, m.address.String(), m.mtu)
	return nil
}

// Start begins packet processing
func (m *Manager) Start() error {
	m.controlMutex.Lock()
	defer m.controlMutex.Unlock()

	if m.iface == nil {
		return fmt.Errorf("interface not created")
	}

	if m.isRunning {
		return fmt.Errorf("interface is already running")
	}

	log.Printf("[TUN] Starting packet processing on interface %s", m.name)

	// Apply routes from configuration
	if err := m.routingMgr.ApplyRoutes(m.name, m.interfaceCfg.Routes); err != nil {
		log.Printf("[TUN] Warning: failed to apply some routes: %v", err)
	}

	// Start packet processing
	m.wg.Add(2) // One for upstream, one for downstream
	m.isRunning = true
	m.stopChan = make(chan struct{})

	go m.processUpstream()
	go m.processDownstream()

	return nil
}

// processUpstream handles packets going from TUN to network
func (m *Manager) processUpstream() {
	defer m.wg.Done()

	buffer := make([]byte, m.mtu)

	for {
		// Check stop signal before blocking read
		select {
		case <-m.stopChan:
			log.Printf("[TUN] Stopping upstream packet processing")
			return
		default:
		}

		if m.iface == nil {
			return
		}

		// Make Read() interruptible by using a goroutine
		readDone := make(chan struct{})
		var n int
		var err error

		go func() {
			n, err = m.iface.Read(buffer)
			close(readDone)
		}()

		// Wait for either read completion or stop signal
		select {
		case <-m.stopChan:
			log.Printf("[TUN] Stopping upstream packet processing")
			return
		case <-readDone:
			// Read completed, process below
		}

		if err != nil {
			if err == io.EOF {
				log.Println("[TUN] Interface closed")
				return
			}
			if strings.Contains(err.Error(), "file already closed") ||
				strings.Contains(err.Error(), "bad file descriptor") {
				log.Printf("[TUN] Interface was closed")
				return
			}
			log.Printf("[TUN] Error reading from interface: %v", err)
			continue
		}

		if n > 0 {
			// Log packet info
			m.logPacketInfo(buffer[:n])

			// Handle packet via upstream handler
			if m.upstreamHandler != nil {
				if err := m.upstreamHandler(buffer[:n], n); err != nil {
					log.Printf("[TUN] Error in upstream handler: %v", err)
				}
			}
		}
	}
}

// processDownstream handles packets going from network to TUN
func (m *Manager) processDownstream() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			log.Printf("[TUN] Stopping downstream packet processing")
			return
		case packet := <-m.downstreamChan:
			if m.iface == nil {
				continue
			}

			// Write packet to TUN interface
			_, err := m.iface.Write(packet)
			if err != nil {
				log.Printf("[TUN] Error writing to interface: %v", err)
			}
		}
	}
}

// WritePacket writes a packet to the TUN interface (downstream)
func (m *Manager) WritePacket(data []byte) error {
	select {
	case m.downstreamChan <- data:
		return nil
	case <-m.stopChan:
		return fmt.Errorf("manager is stopped")
	default:
		return fmt.Errorf("downstream channel is full")
	}
}

// logPacketInfo logs packet information
func (m *Manager) logPacketInfo(packet []byte) {
	if len(packet) < 20 {
		return
	}

	version := packet[0] >> 4
	if version == 4 {
		m.logIPv4Packet(packet)
	} else if version == 6 {
		m.logIPv6Packet(packet)
	}
}

// logIPv4Packet logs IPv4 packet information
func (m *Manager) logIPv4Packet(packet []byte) {
	if len(packet) < 20 {
		return
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	protocol := packet[9]
	protocolName := getProtocolName(protocol)
	log.Printf("[TUN] [PACKET] IPv4: %s -> %s (%s)", srcIP, dstIP, protocolName)
}

// logIPv6Packet logs IPv6 packet information
func (m *Manager) logIPv6Packet(packet []byte) {
	if len(packet) < 40 {
		return
	}

	srcIP := net.IP(packet[8:24])
	dstIP := net.IP(packet[24:40])
	nextHeader := packet[6]
	protocolName := getProtocolName(nextHeader)
	log.Printf("[TUN] [PACKET] IPv6: %s -> %s (%s)", srcIP, dstIP, protocolName)
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
func (m *Manager) Stop() error {
	m.controlMutex.Lock()
	defer m.controlMutex.Unlock()

	if !m.isRunning {
		return fmt.Errorf("interface is not running")
	}

	log.Printf("[TUN] Stopping packet processing on interface %s", m.name)

	// Remove routes
	if err := m.routingMgr.RemoveRoutes(m.name, m.interfaceCfg.Routes); err != nil {
		log.Printf("[TUN] Warning: failed to remove some routes: %v", err)
	}

	// Signal goroutines to stop
	close(m.stopChan)

	// Wait for goroutines to finish
	m.wg.Wait()

	m.isRunning = false
	return nil
}

// Close closes the interface and cleans up resources
func (m *Manager) Close() error {
	if m.isRunning {
		m.Stop()
	}

	m.controlMutex.Lock()
	defer m.controlMutex.Unlock()

	log.Printf("[TUN] Closing interface %s", m.name)

	if m.iface != nil {
		if err := m.iface.Close(); err != nil {
			log.Printf("[TUN] Error closing interface: %v", err)
		}
		m.iface = nil
	}

	return nil
}

// GetStatus returns the current status of the interface
func (m *Manager) GetStatus() map[string]interface{} {
	m.controlMutex.Lock()
	defer m.controlMutex.Unlock()

	status := map[string]interface{}{
		"name":    m.name,
		"mtu":     m.mtu,
		"address": m.address.String(),
		"netmask": m.netmask.String(),
		"up":      m.iface != nil,
		"running": m.isRunning,
	}

	if m.iface != nil {
		iface, err := net.InterfaceByName(m.name)
		if err == nil {
			status["index"] = iface.Index
			status["flags"] = iface.Flags
			status["hardware_addr"] = iface.HardwareAddr.String()
		}
	}

	return status
}
