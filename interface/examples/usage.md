# ThinkPol VPN Interface Usage Examples

This document provides examples of how to use the TUN interface management API.

## Prerequisites

- The application must be run with root privileges (sudo) to create TUN interfaces
- The `water` library must be properly installed

## Starting the Server

```bash
# Run with default port (8080)
sudo go run cmd/main.go

# Run with custom port
sudo go run cmd/main.go -port 9090
```

## API Endpoints

### 1. Create a TUN Interface

```bash
curl -X POST http://localhost:8080/api/interface/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tun0",
    "address": "10.0.0.1",
    "netmask": "255.255.255.0",
    "mtu": 1500
  }'
```

Response:
```json
{
  "status": "success",
  "message": "Interface tun0 created successfully"
}
```

### 2. Get Interface Status

```bash
curl -X GET http://localhost:8080/api/interface/status
```

Response:
```json
{
  "name": "tun0",
  "mtu": 1500,
  "address": "10.0.0.1",
  "netmask": "255.255.255.0",
  "active": true,
  "index": 10,
  "flags": 69,
  "hardware_addr": ""
}
```

### 3. Start Packet Processing

```bash
curl -X POST http://localhost:8080/api/interface/start
```

Response:
```json
{
  "status": "success",
  "message": "Interface started successfully"
}
```

### 4. Configure Interface

```bash
curl -X POST http://localhost:8080/api/interface/configure \
  -H "Content-Type: application/json" \
  -d '{
    "address": "10.0.0.2",
    "netmask": "255.255.255.0",
    "mtu": 1400
  }'
```

### 5. Stop Interface

```bash
curl -X POST http://localhost:8080/api/interface/stop
```

### 6. Delete Interface

```bash
curl -X DELETE http://localhost:8080/api/interface/delete
```

### 7. Health Check

```bash
curl -X GET http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "service": "thinkpol-vpn-interface"
}
```

## Complete Workflow Example

Here's a complete example of creating and using a TUN interface:

```bash
#!/bin/bash

# 1. Start the server
sudo go run cmd/main.go -port 8080 &

# 2. Wait for server to start
sleep 2

# 3. Create interface
curl -X POST http://localhost:8080/api/interface/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tun0",
    "address": "10.0.0.1",
    "netmask": "255.255.255.0",
    "mtu": 1500
  }'

# 4. Check status
curl -X GET http://localhost:8080/api/interface/status

# 5. Start packet processing
curl -X POST http://localhost:8080/api/interface/start

# 6. Test connectivity (in another terminal)
ping 10.0.0.1

# 7. Stop and cleanup
curl -X POST http://localhost:8080/api/interface/stop
curl -X DELETE http://localhost:8080/api/interface/delete
```

## Packet Processing

The interface processes packets in the following way:

1. **IPv4 Packets**: Parses source/destination IPs and protocol
2. **IPv6 Packets**: Parses source/destination IPs and next header
3. **Echo Mode**: Currently echoes packets back (for testing)

To implement custom packet processing:

1. Modify the `handleIPv4Packet` and `handleIPv6Packet` methods in `internal/tun/manager.go`
2. Add encryption/decryption logic
3. Implement routing to remote endpoints
4. Add firewall rules

## Troubleshooting

### Permission Denied
```bash
# Make sure to run with sudo
sudo go run cmd/main.go
```

### Interface Already Exists
```bash
# Delete existing interface first
sudo ifconfig tun0 destroy
```

### Port Already in Use
```bash
# Use a different port
sudo go run cmd/main.go -port 9090
```

### System Commands Not Found
Make sure `ifconfig` and `route` commands are available on your system.

## Security Considerations

- Always run with appropriate privileges
- Validate all input parameters
- Consider implementing authentication for the API
- Use HTTPS in production environments
- Implement proper logging and monitoring 