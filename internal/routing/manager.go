package routing

import (
	"fmt"
	"log"
	"thinkpol-vpn/internal/config"
	"thinkpol-vpn/internal/platform"
)

// Manager handles routing operations with platform-specific implementations
type Manager struct {
	systemManager platform.SystemInterface
}

// ConfigureInterface configures the interface with IP, netmask, and MTU
func (rm *Manager) ConfigureInterface(name string, addr, netmask string, mtu int) error {
	return rm.systemManager.ConfigureInterface(name, addr, netmask, mtu)
}

// DeleteInterface removes the interface
func (rm *Manager) DeleteInterface(name string) error {
	return rm.systemManager.DeleteInterface(name)
}

// NewManager creates a new routing manager based on the detected platform
func NewManager() (*Manager, error) {
	platformType := platform.Detect()
	if !platformType.IsSupported() {
		return nil, fmt.Errorf("unsupported platform: %s", platformType)
	}

	systemManager := newSystemManager()
	if systemManager == nil {
		return nil, fmt.Errorf("failed to create system manager for platform: %s", platformType)
	}

	return &Manager{
		systemManager: systemManager,
	}, nil
}

// ApplyRoutes applies all routes from the configuration
func (rm *Manager) ApplyRoutes(interfaceName string, routes []config.Route) error {
	gateway, err := rm.systemManager.GetDefaultGateway()
	if err != nil {
		log.Printf("[ROUTING] Warning: could not get default gateway: %v", err)
		gateway = "" // Continue without gateway
	}

	for _, route := range routes {
		if err := rm.AddRoute(interfaceName, route.Destination, route.Gateway, gateway); err != nil {
			log.Printf("[ROUTING] Warning: failed to add route %s: %v", route.Destination, err)
			// Continue with other routes
		} else {
			log.Printf("[ROUTING] Added route %s via %s", route.Destination, interfaceName)
		}
	}

	return nil
}

// RemoveRoutes removes all routes from the configuration
func (rm *Manager) RemoveRoutes(interfaceName string, routes []config.Route) error {
	gateway, err := rm.systemManager.GetDefaultGateway()
	if err != nil {
		log.Printf("[ROUTING] Warning: could not get default gateway: %v", err)
		gateway = "" // Continue without gateway
	}

	for _, route := range routes {
		if err := rm.DeleteRoute(interfaceName, route.Destination, route.Gateway, gateway); err != nil {
			log.Printf("[ROUTING] Warning: failed to delete route %s: %v", route.Destination, err)
			// Continue with other routes
		}
	}

	return nil
}

// AddRoute adds a single route
func (rm *Manager) AddRoute(interfaceName, destination, routeGateway, defaultGateway string) error {
	// For interface routes, don't pass gateway - pass empty string and let platform handle it
	// Only use gateway if explicitly specified in route config
	gateway := routeGateway
	
	// Don't use default gateway for interface routes - interface routes don't need gateway
	return rm.systemManager.AddRoute(interfaceName, destination, gateway)
}

// DeleteRoute removes a single route
func (rm *Manager) DeleteRoute(interfaceName, destination, routeGateway, defaultGateway string) error {
	// Use route-specific gateway if provided, otherwise use default gateway
	gateway := routeGateway
	if gateway == "" {
		gateway = defaultGateway
	}

	return rm.systemManager.DeleteRoute(interfaceName, destination, gateway)
}
