# ThinkPol VPN Interface

This is the interface component of the ThinkPol VPN project, written in Go.

## Project Structure

```
interface/
├── cmd/           # Main application entry points
├── internal/      # Private application code
├── pkg/           # Public libraries that can be used by other applications
├── go.mod         # Go module definition
└── README.md      # This file
```

## Getting Started

### Prerequisites

- Go 1.21 or later

### Running the Application

```bash
# Navigate to the interface directory
cd interface

# Run the application
go run cmd/main.go
```

The server will start on port 8080. You can access it at `http://localhost:8080`.

### Building

```bash
# Build the binary
go build -o bin/interface cmd/main.go

# Run the binary
./bin/interface
```

## Development

This project follows standard Go project layout conventions:

- `cmd/`: Contains the main applications
- `internal/`: Private application and library code
- `pkg/`: Library code that's ok to use by external applications

## License

See the main project LICENSE file. 