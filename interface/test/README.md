# ThinkPol VPN Interface Tests

This directory contains test scripts for the ThinkPol VPN Interface application.

## Test Structure

### Core Files
- **`test_utils.sh`** - Shared utilities and functions used by all test scripts
- **`run_tests.sh`** - Test runner that executes all numbered tests in order
- **`01_basics.sh`** - Basic interface management tests (create, start, stop, delete)
- **`02_traffic.sh`** - Traffic processing and packet logging tests
- **`__UNSAFE__routeall.sh`** - Unsafe tests for traffic interception (⚠️ DANGEROUS)

### Backup Files
- **`01_basics_old.sh`** - Original e2e.sh file (backup)
- **`__UNSAFE__routeall_old.sh`** - Original e2e_unsafe.sh file (backup)

## Prerequisites

1. **Root privileges** - All tests require sudo access
2. **Server running** - The VPN interface server must be running
3. **Network tools** - `curl`, `ping`, `nc` (netcat) must be available

## Running Tests

### Option 1: Run All Tests (Recommended)

```bash
cd test
sudo ./run_tests.sh
```

This will automatically:
- Find all test files starting with two digits (e.g., `01_`, `02_`, etc.)
- Run them in numerical order
- Provide a summary of results

**Available options:**
```bash
sudo ./run_tests.sh --help     # Show help
sudo ./run_tests.sh --list     # List available tests without running
sudo ./run_tests.sh --server   # Skip server check (assume server is running)
```

### Option 2: Run Individual Tests

#### 1. Start the Server

```bash
# For basic tests
sudo go run cmd/main.go -port 8080

# For unsafe tests (⚠️ DANGEROUS)
sudo go run cmd/main.go -port 8080 -unsafe
```

#### 2. Run Basic Tests

```bash
cd test
sudo ./01_basics.sh
```

**Tests included:**
- Health endpoint
- Interface creation/deletion
- Interface start/stop
- Error handling
- Complete lifecycle

#### 3. Run Traffic Tests

```bash
cd test
sudo ./02_traffic.sh
```

**Tests included:**
- ICMP traffic processing
- TCP traffic processing
- UDP traffic processing
- Mixed traffic processing
- Packet logging format verification

#### 4. Run Unsafe Tests (⚠️ DANGEROUS)

```bash
cd test
sudo ./__UNSAFE__routeall.sh
```

**⚠️ WARNING: This will intercept ALL internet traffic!**

**Tests included:**
- Traffic interception
- Packet logging
- Route restoration

## Test Runner

The `run_tests.sh` script provides automated test execution:

### Features
- **Automatic discovery** - Finds all test files matching `[0-9][0-9]_*.sh` pattern
- **Numerical ordering** - Runs tests in order by their number prefix
- **Progress tracking** - Shows current test and total count
- **Summary reporting** - Provides detailed results at the end
- **Error handling** - Continues running tests even if some fail
- **Cleanup** - Automatically cleans up after all tests

### Usage Examples
```bash
# Run all numbered tests
sudo ./run_tests.sh

# List available tests without running
./run_tests.sh --list

# Skip server check (useful for CI/CD)
sudo ./run_tests.sh --server

# Show help
./run_tests.sh --help
```

### Expected Output
```
[TEST RUNNER] ThinkPol VPN Interface Test Runner
==================================================
[TEST RUNNER] ✓ Root privileges confirmed
[TEST RUNNER] ✓ Server is running on port 8080
[TEST RUNNER] ✓ Server is ready!
[TEST RUNNER] Finding test files...
[INFO] Found 2 test file(s):
[INFO]   - 01_basics.sh
[INFO]   - 02_traffic.sh

[TEST RUNNER] Starting test execution...

[TEST RUNNER] Test 1/2: 01_basics.sh
[TEST RUNNER] Running test: 01_basics.sh
==================================================
... test output ...
[INFO] ✓ 01_basics.sh completed successfully
==================================================

[TEST RUNNER] Test 2/2: 02_traffic.sh
[TEST RUNNER] Running test: 02_traffic.sh
==================================================
... test output ...
[INFO] ✓ 02_traffic.sh completed successfully
==================================================

[TEST RUNNER] Test Execution Summary
==================================================
[INFO] Total tests: 2
[INFO] Passed: 2
[ERROR] Failed: 0
==================================================
[INFO] All tests passed! 🎉
```

## Test Utilities

The `test_utils.sh` file provides shared functions:

### Setup Functions
- `check_root()` - Verify root privileges
- `check_server()` - Check if server is running
- `check_server_unsafe()` - Check if server is running with unsafe mode
- `wait_for_server()` - Wait for server to be ready

### API Functions
- `create_interface()` - Create TUN interface
- `start_interface()` - Start packet processing
- `stop_interface()` - Stop packet processing
- `delete_interface()` - Delete interface
- `get_interface_status()` - Get interface status
- `test_health()` - Test health endpoint

### Traffic Generation Functions
- `generate_icmp_traffic(target_ip, count)` - Generate ICMP traffic
- `generate_tcp_traffic(target_ip, port)` - Generate TCP traffic
- `generate_udp_traffic(target_ip, port)` - Generate UDP traffic
- `generate_mixed_traffic(target_ip)` - Generate mixed traffic types

### Test Helper Functions
- `test_interface_lifecycle()` - Complete interface lifecycle test
- `test_error_handling()` - Error handling tests
- `test_no_interface_operations()` - Tests for non-existent interface

### Cleanup Functions
- `cleanup()` - Clean up interfaces
- `setup_cleanup()` - Set up cleanup trap

## Configuration

All test scripts use the following configuration (defined in `test_utils.sh`):

```bash
SERVER_PORT=8080
INTERFACE_NAME="utun9"
INTERFACE_IP="10.0.0.1"
INTERFACE_NETMASK="255.255.255.0"
INTERFACE_MTU=1500
```

## Expected Output

### Packet Logging Format
When traffic tests are running, you should see packet logs in the server output:

```
[PACKET] IPv4: 192.168.1.100 -> 10.0.0.1 (ICMP)
[PACKET] IPv4: 10.0.0.1 -> 192.168.1.100 (ICMP)
[PACKET] IPv4: 192.168.1.100 -> 10.0.0.1 (TCP)
```

### Test Output
Tests provide colored output with status indicators:
- 🟢 `[INFO]` - Information messages
- 🟡 `[WARN]` - Warning messages
- 🔴 `[ERROR]` - Error messages
- 🔵 `[SETUP]` - Setup messages

## Troubleshooting

### Common Issues

1. **Permission denied** - Run with `sudo`
2. **Server not running** - Start the server first
3. **Interface already exists** - Run cleanup or restart server
4. **Network connectivity issues** - Check routing after unsafe tests

### Cleanup

If tests fail or leave interfaces behind:

```bash
# Manual cleanup
curl -X POST http://localhost:8080/api/interface/stop
curl -X DELETE http://localhost:8080/api/interface/delete

# Or restart the server
pkill -f "go run cmd/main.go"
```

## Adding New Tests

To add new tests:

1. Create a new test file (e.g., `03_new_feature.sh`)
2. Source the utilities: `source "$SCRIPT_DIR/test_utils.sh"`
3. Use the shared functions from `test_utils.sh`
4. Follow the existing pattern for setup, tests, and cleanup

Example:
```bash
#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test_utils.sh"

main() {
    setup_cleanup
    check_root
    check_server
    wait_for_server
    
    # Your tests here
    log_info "Running new feature tests..."
    
    echo ""
    log_info "All new feature tests passed! 🎉"
}

main "$@"
``` 