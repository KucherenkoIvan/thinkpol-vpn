package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// InterfaceConfig holds TUN interface configuration
type InterfaceConfig struct {
	Address string `json:"address"`
	Netmask string `json:"netmask"`
	MTU     int    `json:"mtu"`
	Routes  []Route `json:"routes,omitempty"`
}

// Route defines a routing rule
type Route struct {
	Destination string `json:"destination"` // CIDR notation, e.g., "10.0.0.0/24"
	Gateway     string `json:"gateway,omitempty"`
}

// LoadInterfaceConfig loads interface configuration from a JSON file
func LoadInterfaceConfig(path string) (*InterfaceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config struct {
		Interface InterfaceConfig `json:"interface"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if not specified
	if config.Interface.MTU == 0 {
		config.Interface.MTU = 1500
	}

	if err := validateInterfaceConfig(&config.Interface); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config.Interface, nil
}

func validateInterfaceConfig(config *InterfaceConfig) error {
	if config.Address == "" {
		return fmt.Errorf("interface address is required")
	}
	if config.Netmask == "" {
		return fmt.Errorf("interface netmask is required")
	}
	if config.MTU < 68 || config.MTU > 65535 {
		return fmt.Errorf("MTU must be between 68 and 65535")
	}
	return nil
}
