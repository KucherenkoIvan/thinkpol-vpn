package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// TransportConfig holds transport service configuration
type TransportConfig struct {
	ServiceAddress  string `json:"service_address"`  // gRPC endpoint for transport service, e.g., "localhost:50052"
	GatewayAddress  string `json:"gateway_address"` // Gateway server address for client-initiated connection
}

// LoadTransportConfig loads transport configuration from a JSON file
func LoadTransportConfig(path string) (*TransportConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config struct {
		Transport TransportConfig `json:"transport"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validateTransportConfig(&config.Transport); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config.Transport, nil
}

func validateTransportConfig(config *TransportConfig) error {
	if config.ServiceAddress == "" {
		return fmt.Errorf("transport service address is required")
	}
	if config.GatewayAddress == "" {
		return fmt.Errorf("gateway address is required")
	}
	return nil
}
