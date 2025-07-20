# ThinkPol VPN Interface

A Go application for managing virtual network interfaces (TUN/TAP) with a RESTful API. This application provides a foundation for building VPN solutions by allowing you to create, configure, and manage virtual network interfaces programmatically.

## Features

- **TUN Interface Management**: Create and manage TUN (Layer 3) virtual interfaces
- **RESTful API**: HTTP API for interface operations
- **Packet Processing**: Real-time packet capture and processing
- **Cross-platform**: Works on macOS, Linux, and Windows
- **Configuration Management**: JSON-based configuration
- **Health Monitoring**: Built-in health checks and status monitoring

## Architecture

```
interface/
├── cmd/main.go              # Application entry point
├── internal/
│   ├── tun/
│   │   ├── manager.go       # TUN interface manager
│   │   └── system.go        # System-level operations
│   └── api/
│       └── server.go        # HTTP API server
├── config.json              # Configuration file
├── examples/usage.md        # Usage examples
└── test.sh                  # Test script
```

### Core Components

1. **Interface Manager** (`internal/tun/manager.go`)
   - Creates and manages TUN interfaces
   - Handles packet processing
   - Provides interface status information

2. **System Manager** (`internal/tun/system.go`)
   - Executes system commands for interface configuration
   - Manages IP addresses, MTU, and interface state
   - Handles routing operations

3. **API Server** (`internal/api/server.go`)
   - RESTful HTTP API for interface management
   - JSON-based request/response format
   - Input validation and error handling

## Prerequisites

- Go 1.23.4 or later
- Root privileges (for TUN interface creation)
- `ifconfig` and `route` commands available

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd thinkpol-vpn/interface
```

2. Install dependencies:
```bash
go mod tidy
```

3. Build the application:
```bash
go build -o vpn-interface cmd/main.go
```

## Usage

### Starting the Server

```bash
# Run with default port (8080)
sudo go run cmd/main.go

# Run with custom port
sudo go run cmd/main.go -port 9090
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/interface/create` | Create TUN interface |
| GET | `/api/interface/status` | Get interface status |
| POST | `/api/interface/start` | Start packet processing |
| POST | `/api/interface/stop` | Stop packet processing |
| DELETE | `/api/interface/delete` | Delete interface |
| POST | `/api/interface/configure` | Configure interface |

### Example Usage

```bash
# Create a TUN interface
curl -X POST http://localhost:8080/api/interface/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tun0",
    "address": "10.0.0.1",
    "netmask": "255.255.255.0",
    "mtu": 1500
  }'

# Get interface status
curl -X GET http://localhost:8080/api/interface/status

# Start packet processing
curl -X POST http://localhost:8080/api/interface/start
```

## Configuration

The application can be configured using `config.json`:

```json
{
  "interface": {
    "name": "tun0",
    "address": "10.0.0.1",
    "netmask": "255.255.255.0",
    "mtu": 1500
  },
  "server": {
    "port": 8080,
    "host": "localhost"
  },
  "logging": {
    "level": "info",
    "file": "vpn-interface.log"
  }
}
```

## Testing

Run the test script to verify functionality:

```bash
# Make sure the server is running first
sudo go run cmd/main.go &

# Run tests
sudo ./test.sh
```

## Development

### Project Structure

```
interface/
├── cmd/                    # Application entry points
├── internal/              # Private application code
│   ├── tun/              # TUN interface management
│   └── api/              # HTTP API implementation
├── pkg/                   # Public libraries (if any)
├── config.json           # Configuration
├── examples/             # Usage examples
└── test.sh              # Test script
```

### Adding New Features

1. **Packet Processing**: Modify `handleIPv4Packet` and `handleIPv6Packet` methods in `manager.go`
2. **API Endpoints**: Add new handlers in `server.go`
3. **System Operations**: Extend `system.go` with new system commands

### Building for Production

```bash
# Build for current platform
go build -o vpn-interface cmd/main.go

# Build for specific platforms
GOOS=linux GOARCH=amd64 go build -o vpn-interface-linux cmd/main.go
GOOS=darwin GOARCH=amd64 go build -o vpn-interface-macos cmd/main.go
```

## Security Considerations

- **Privileges**: Always run with appropriate privileges for TUN interface creation
- **Input Validation**: All API inputs are validated
- **Network Security**: Consider implementing authentication for production use
- **HTTPS**: Use HTTPS in production environments
- **Logging**: Implement proper logging and monitoring

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Run with sudo
   sudo go run cmd/main.go
   ```

2. **Interface Already Exists**
   ```bash
   # Delete existing interface
   sudo ifconfig tun0 destroy
   ```

3. **Port Already in Use**
   ```bash
   # Use different port
   sudo go run cmd/main.go -port 9090
   ```

### Debug Mode

Enable debug logging by modifying the log level in the code or configuration.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Roadmap

- [ ] TAP interface support
- [ ] IPv6 support improvements
- [ ] Authentication and authorization
- [ ] WebSocket support for real-time updates
- [ ] Configuration hot-reload
- [ ] Metrics and monitoring
- [ ] Docker support
- [ ] Kubernetes deployment 