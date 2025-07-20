#!/bin/bash

# ThinkPol VPN Interface Test Utilities
# This file contains shared functions and configurations for all test scripts

# Configuration
SERVER_PORT=8080
INTERFACE_NAME="utun9"
INTERFACE_IP="10.0.0.1"
INTERFACE_NETMASK="255.255.255.0"
INTERFACE_MTU=1500

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_setup() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

# =============================================================================
# SETUP FUNCTIONS
# =============================================================================

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    log_setup "✓ Root privileges confirmed"
}

# Check if server is running
check_server() {
    if ! curl -s http://localhost:$SERVER_PORT/health > /dev/null; then
        log_error "Server is not running on port $SERVER_PORT"
        log_info "Start the server with: sudo go run cmd/main.go -port $SERVER_PORT"
        exit 1
    fi
    log_setup "✓ Server is running on port $SERVER_PORT"
}

# Check if server is running with unsafe mode
check_server_unsafe() {
    if ! curl -s http://localhost:$SERVER_PORT/health > /dev/null; then
        log_error "Server is not running on port $SERVER_PORT"
        log_info "Start the server with: sudo go run cmd/main.go -port $SERVER_PORT -unsafe"
        exit 1
    fi
    log_setup "✓ Server is running on port $SERVER_PORT"
}

# Wait for server to be ready
wait_for_server() {
    log_setup "Waiting for server to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:$SERVER_PORT/health > /dev/null; then
            log_setup "✓ Server is ready!"
            return 0
        fi
        sleep 1
    done
    log_error "Server did not become ready in time"
    exit 1
}

# =============================================================================
# API FUNCTIONS
# =============================================================================

# Create interface
create_interface() {
    log_info "Creating interface..."
    response=$(curl -s -X POST http://localhost:$SERVER_PORT/api/interface/create)
    if echo "$response" | grep -q "success"; then
        log_info "✓ Interface creation successful"
        return 0
    else
        log_error "✗ Interface creation failed: $response"
        return 1
    fi
}

# Start interface
start_interface() {
    log_info "Starting interface..."
    response=$(curl -s -X POST http://localhost:$SERVER_PORT/api/interface/start)
    if echo "$response" | grep -q "success"; then
        log_info "✓ Interface start successful"
        return 0
    else
        log_error "✗ Interface start failed: $response"
        return 1
    fi
}

# Stop interface
stop_interface() {
    log_info "Stopping interface..."
    response=$(curl -s -X POST http://localhost:$SERVER_PORT/api/interface/stop)
    if echo "$response" | grep -q "success"; then
        log_info "✓ Interface stop successful"
        return 0
    else
        log_error "✗ Interface stop failed: $response"
        return 1
    fi
}

# Delete interface
delete_interface() {
    log_info "Deleting interface..."
    response=$(curl -s -X DELETE http://localhost:$SERVER_PORT/api/interface/delete)
    if echo "$response" | grep -q "success"; then
        log_info "✓ Interface deletion successful"
        return 0
    else
        log_error "✗ Interface deletion failed: $response"
        return 1
    fi
}

# Get interface status
get_interface_status() {
    response=$(curl -s http://localhost:$SERVER_PORT/api/interface/status)
    echo "$response"
}

# Test health endpoint
test_health() {
    log_info "Testing health endpoint..."
    response=$(curl -s http://localhost:$SERVER_PORT/health)
    if echo "$response" | grep -q "healthy"; then
        log_info "✓ Health check passed"
        return 0
    else
        log_error "✗ Health check failed: $response"
        return 1
    fi
}

# =============================================================================
# TRAFFIC GENERATION FUNCTIONS
# =============================================================================

# Generate ICMP traffic
generate_icmp_traffic() {
    local target_ip=${1:-$INTERFACE_IP}
    local count=${2:-3}
    log_info "Generating ICMP traffic to $target_ip..."
    
    ping -c $count -t 1 $target_ip > /dev/null 2>&1 &
    local ping_pid=$!
    wait $ping_pid
    
    log_info "✓ ICMP traffic generated"
}

# Generate TCP traffic
generate_tcp_traffic() {
    local target_ip=${1:-$INTERFACE_IP}
    local port=${2:-8080}
    log_info "Generating TCP traffic to $target_ip:$port..."
    
    curl -s --connect-timeout 2 http://$target_ip:$port/health > /dev/null 2>&1 &
    local curl_pid=$!
    wait $curl_pid
    
    log_info "✓ TCP traffic generated"
}

# Generate UDP traffic
generate_udp_traffic() {
    local target_ip=${1:-$INTERFACE_IP}
    local port=${2:-53}
    log_info "Generating UDP traffic to $target_ip:$port..."
    
    echo "test" | nc -u -w 1 $target_ip $port > /dev/null 2>&1 &
    local nc_pid=$!
    wait $nc_pid
    
    log_info "✓ UDP traffic generated"
}

# Generate mixed traffic
generate_mixed_traffic() {
    local target_ip=${1:-$INTERFACE_IP}
    log_info "Generating mixed traffic to $target_ip..."
    
    # Send multiple types of traffic simultaneously
    ping -c 2 -t 1 $target_ip > /dev/null 2>&1 &
    local ping_pid=$!
    
    curl -s --connect-timeout 2 http://$target_ip:8080/health > /dev/null 2>&1 &
    local curl_pid=$!
    
    echo "test" | nc -u -w 1 $target_ip 53 > /dev/null 2>&1 &
    local nc_pid=$!
    
    # Wait for all processes to complete
    wait $ping_pid $curl_pid $nc_pid
    
    log_info "✓ Mixed traffic generated"
}

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    # Try to stop and delete interface if it exists
    curl -s -X POST http://localhost:$SERVER_PORT/api/interface/stop > /dev/null 2>&1 || true
    sleep 1
    curl -s -X DELETE http://localhost:$SERVER_PORT/api/interface/delete > /dev/null 2>&1 || true
    sleep 1
}

# Setup cleanup trap
setup_cleanup() {
    trap cleanup EXIT
}

# =============================================================================
# TEST HELPER FUNCTIONS
# =============================================================================

# Test interface lifecycle
test_interface_lifecycle() {
    log_info "Testing complete interface lifecycle..."
    
    # Check current status first
    log_info "Checking interface status before lifecycle test..."
    status_response=$(get_interface_status)
    log_info "Current status: $status_response"
    
    # Create interface
    if ! create_interface; then
        return 1
    fi
    
    # Start interface
    if ! start_interface; then
        return 1
    fi
    
    # Stop interface
    if ! stop_interface; then
        return 1
    fi
    
    # Delete interface
    if ! delete_interface; then
        return 1
    fi
    
    # Small delay to ensure cleanup completes
    sleep 1
    
    log_info "✓ Interface lifecycle test completed successfully"
    return 0
}

# Test error handling
test_error_handling() {
    log_info "Testing error handling..."
    
    # First, create an interface
    if ! create_interface; then
        return 1
    fi
    
    # Test creating interface twice (should fail with 409)
    response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:$SERVER_PORT/api/interface/create)
    http_code=$(echo "$response" | tail -n 1)
    response_body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "409" ]; then
        log_info "✓ Duplicate create error handling successful"
    else
        log_error "✗ Duplicate create error handling failed: HTTP $http_code, Response: $response_body"
        return 1
    fi
    
    # Test starting twice - first ensure interface is running
    response=$(curl -s -X POST http://localhost:$SERVER_PORT/api/interface/start)
    if echo "$response" | grep -q "already running"; then
        log_info "✓ Duplicate start error handling successful"
    else
        log_error "✗ Duplicate start error handling failed: $response"
        log_info "Expected 'already running' but got: $response"
        
        # Debug: check interface status
        status_response=$(get_interface_status)
        log_info "Interface status after first start: $status_response"
        
        # Wait for interface to be running and try again
        sleep 2
        status_response2=$(get_interface_status)
        log_info "Interface status after delay: $status_response2"
        
        response2=$(curl -s -X POST http://localhost:$SERVER_PORT/api/interface/start)
        log_info "Second attempt response: $response2"
        return 1
    fi
    
    # Test stopping twice
    stop_interface > /dev/null
    response=$(curl -s -X POST http://localhost:$SERVER_PORT/api/interface/stop)
    if echo "$response" | grep -q "not running"; then
        log_info "✓ Duplicate stop error handling successful"
    else
        log_error "✗ Duplicate stop error handling failed: $response"
        return 1
    fi
    
    # Clean up - delete the interface after error handling tests
    log_info "Cleaning up interface after error handling tests..."
    if ! delete_interface; then
        return 1
    fi
    
    # Small delay to ensure cleanup completes
    sleep 1
    
    log_info "✓ Error handling tests completed successfully"
    return 0
}

# Test operations on non-existent interface
test_no_interface_operations() {
    log_info "Testing operations on non-existent interface..."
    
    # Test status when no interface exists
    response=$(get_interface_status)
    if echo "$response" | grep -q "no_interface"; then
        log_info "✓ No interface status check successful"
    else
        log_error "✗ No interface status check failed: $response"
        return 1
    fi
    
    # Test start when no interface exists
    response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:$SERVER_PORT/api/interface/start)
    http_code=$(echo "$response" | tail -n 1)
    response_body=$(echo "$response" | sed '$d')
    if [ "$http_code" = "400" ]; then
        log_info "✓ Start without interface error handling successful"
    else
        log_error "✗ Start without interface error handling failed: HTTP $http_code, Response: $response_body"
        return 1
    fi
    
    # Test stop when no interface exists
    response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:$SERVER_PORT/api/interface/stop)
    http_code=$(echo "$response" | tail -n 1)
    response_body=$(echo "$response" | sed '$d')
    if [ "$http_code" = "400" ]; then
        log_info "✓ Stop without interface error handling successful"
    else
        log_error "✗ Stop without interface error handling failed: HTTP $http_code, Response: $response_body"
        return 1
    fi
    
    # Test delete when no interface exists
    response=$(curl -s -w "\n%{http_code}" -X DELETE http://localhost:$SERVER_PORT/api/interface/delete)
    http_code=$(echo "$response" | tail -n 1)
    response_body=$(echo "$response" | sed '$d')
    if [ "$http_code" = "400" ]; then
        log_info "✓ Delete without interface error handling successful"
    else
        log_error "✗ Delete without interface error handling failed: HTTP $http_code, Response: $response_body"
        return 1
    fi
    
    log_info "✓ No interface operations tests completed successfully"
    return 0
} 