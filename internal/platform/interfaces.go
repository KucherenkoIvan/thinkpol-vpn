package platform

// TUNInterface defines the interface that platform-specific TUN implementations must satisfy
type TUNInterface interface {
	// Create creates a new TUN interface
	Create() error

	// Close closes the TUN interface
	Close() error

	// Read reads a packet from the TUN interface
	Read(buffer []byte) (int, error)

	// Write writes a packet to the TUN interface
	Write(buffer []byte) (int, error)

	// Name returns the name of the TUN interface
	Name() string

	// MTU returns the MTU of the TUN interface
	MTU() (int, error)
}

// SystemInterface defines the interface for system-level operations
type SystemInterface interface {
	// ConfigureInterface configures the interface with IP, netmask, and MTU
	ConfigureInterface(name string, addr, netmask string, mtu int) error

	// AddRoute adds a route for the interface
	AddRoute(interfaceName, destination, gateway string) error

	// DeleteRoute removes a route for the interface
	DeleteRoute(interfaceName, destination, gateway string) error

	// DeleteInterface removes the interface
	DeleteInterface(name string) error

	// GetDefaultGateway returns the default gateway
	GetDefaultGateway() (string, error)
}
