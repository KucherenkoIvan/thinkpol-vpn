.PHONY: protobuf compile prod clean help deps

# Default target
all: help

# Compile protobuf files
protobuf:
	@echo "Compiling protobuf files..."
	@protoc --go_out=. --go_opt=paths=source_relative \
		api/protobuf/*.proto
	@echo "Protobuf compilation complete"

# Install Go module dependencies
deps:
	@echo "Installing Go module dependencies..."
	@go mod download
	@go mod tidy
	@echo "Dependencies installed and cleaned"

# Build for development (with debug symbols)
compile:
	@echo "Building for development..."
	@go build -o bin/thinkpol-vpn \
		-gcflags="all=-N -l" \
		-ldflags="-X main.version=dev" \
		./cmd/main.go
	@echo "Development build complete: bin/thinkpol-vpn"

# Build for production (optimized, stripped)
prod: deps protobuf
	@echo "Building for production..."
	@go build -o bin/thinkpol-vpn-prod \
		-ldflags="-s -w -X main.version=prod" \
		./cmd/main.go
	@echo "Production build complete: bin/thinkpol-vpn-prod"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f api/protobuf/*.pb.go
	@echo "Clean complete"

# Show help
help:
	@echo "Available targets:"
	@echo "  help			- Show this help message"
	@echo "  deps			- Install Go module dependencies"
	@echo "  protobuf		- Compile protobuf files"
	@echo "  compile		- Build for development (debug symbols)"
	@echo "  clean			- Remove build artifacts"
	@echo "  prod 			- Build for production (optimized)"
