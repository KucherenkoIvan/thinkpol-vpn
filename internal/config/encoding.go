package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// EncodingConfig holds encoding service configuration
type EncodingConfig struct {
	ServiceAddress string            `json:"service_address"` // gRPC endpoint, e.g., "localhost:50051"
	Type           string            `json:"type"`            // encoding type, e.g., "base64"
	Options        map[string]string `json:"options,omitempty"` // type-specific options
}

// LoadEncodingConfig loads encoding configuration from a JSON file
func LoadEncodingConfig(path string) (*EncodingConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config struct {
		Encoding EncodingConfig `json:"encoding"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validateEncodingConfig(&config.Encoding); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config.Encoding, nil
}

func validateEncodingConfig(config *EncodingConfig) error {
	if config.ServiceAddress == "" {
		return fmt.Errorf("encoding service address is required")
	}
	if config.Type == "" {
		return fmt.Errorf("encoding type is required")
	}
	return nil
}
