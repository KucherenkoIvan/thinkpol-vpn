.PHONY: all build clean gateway encoding-service transport-service client services test run-gateway run-encoding run-transport run-client

# Build all binaries
all: gateway encoding-service transport-service client

# Individual service builds
gateway:
	@echo "Building gateway server..."
	@go build -o bin/gateway cmd/gateway/main.go
	@echo "✅ Gateway built: bin/gateway"

encoding-service:
	@echo "Building encoding service..."
	@go build -o bin/encoding-service cmd/encoding-service/main.go
	@echo "✅ Encoding service built: bin/encoding-service"

transport-service:
	@echo "Building transport service..."
	@go build -o bin/transport-service cmd/transport-service/main.go
	@echo "✅ Transport service built: bin/transport-service"

client:
	@echo "Building VPN client..."
	@go build -o bin/client cmd/client/main.go
	@echo "✅ Client built: bin/client"

# Build all services (excluding client which needs special permissions)
services: gateway encoding-service transport-service

# Build everything
build: all

# Clean binaries
clean:
	@echo "Cleaning binaries..."
	@rm -rf bin/
	@echo "✅ Cleaned"

# Run targets (for development)
run-gateway: gateway
	@echo "Starting gateway server..."
	@./bin/gateway

run-encoding: encoding-service
	@echo "Starting encoding service..."
	@./bin/encoding-service

run-transport: transport-service
	@echo "Starting transport service..."
	@./bin/transport-service

run-client: client
	@echo "Starting VPN client (requires sudo)..."
	@sudo ./bin/client

# Test targets
test:
	@echo "Running tests..."
	@go test ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	@golangci-lint run ./... || echo "Install golangci-lint for linting"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy
	@echo "✅ Dependencies installed"

# Help
help:
	@echo "Available targets:"
	@echo "  make all              - Build all binaries (gateway, encoding-service, transport-service, client)"
	@echo "  make services         - Build all services (excluding client)"
	@echo "  make gateway          - Build gateway server only"
	@echo "  make encoding-service - Build encoding service only"
	@echo "  make transport-service - Build transport service only"
	@echo "  make client           - Build client only"
	@echo "  make clean            - Remove all built binaries"
	@echo "  make test             - Run tests"
	@echo "  make fmt              - Format code"
	@echo "  make deps             - Install/update dependencies"
	@echo ""
	@echo "Run targets (development):"
	@echo "  make run-gateway      - Build and run gateway"
	@echo "  make run-encoding     - Build and run encoding service"
	@echo "  make run-transport    - Build and run transport service"
	@echo "  make run-client       - Build and run client (requires sudo)"

