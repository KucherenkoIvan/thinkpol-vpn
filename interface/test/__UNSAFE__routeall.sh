#!/bin/bash

# ThinkPol VPN Interface UNSAFE Test Script
# This script tests unsafe features like traffic interception
# ⚠️  WARNING: This will intercept ALL internet traffic!
# ⚠️  Only run this in a controlled environment!

set -e

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test_utils.sh"

# =============================================================================
# UNSAFE TESTS
# =============================================================================

# Test traffic interception
test_intercept() {
    log_warn "⚠️  TESTING TRAFFIC INTERCEPTION - ALL INTERNET TRAFFIC WILL BE LOGGED!"
    log_warn "⚠️  This will redirect all your internet traffic through the TUN interface"
    log_warn "⚠️  Press Ctrl+C now if you don't want this to happen"
    
    # Give user 5 seconds to cancel
    for i in {5..1}; do
        echo -n "Starting in $i seconds... "
        sleep 1
        echo
    done
    
    log_info "Testing traffic interception..."
    response=$(curl -s -X POST http://localhost:$SERVER_PORT/api/interface/intercept)
    
    if echo "$response" | grep -q "success"; then
        log_info "Traffic interception successful"
        log_warn "⚠️  WARNING: All internet traffic is now being intercepted!"
        log_warn "⚠️  Your browsing activity will be logged by this application"
        log_warn "⚠️  Internet connectivity may be affected"
        
        # Test that we can still access the internet
        log_info "Testing internet connectivity..."
        if curl -s --connect-timeout 5 https://www.google.com > /dev/null; then
            log_info "Internet connectivity test passed"
        else
            log_warn "Internet connectivity test failed - routing may be broken"
        fi
        
    else
        log_error "Traffic interception failed: $response"
        exit 1
    fi
}

# Test packet logging
test_packet_logging() {
    log_info "Testing packet logging..."
    log_warn "Generating some test traffic to see packet logging..."
    
    # Generate some test traffic
    curl -s https://httpbin.org/ip > /dev/null &
    curl -s https://httpbin.org/user-agent > /dev/null &
    ping -c 3 8.8.8.8 > /dev/null &
    
    log_info "Check the server logs to see packet information"
    log_info "You should see IPv4 packets being logged"
}

# Test restore functionality
test_restore() {
    log_info "Testing route restoration..."
    
    # Delete the interface (this should restore routes)
    response=$(curl -s -X DELETE http://localhost:$SERVER_PORT/api/interface/delete)
    
    if echo "$response" | grep -q "success"; then
        log_info "Interface deletion and route restoration successful"
        
        # Test internet connectivity after restoration
        log_info "Testing internet connectivity after restoration..."
        if curl -s --connect-timeout 5 https://www.google.com > /dev/null; then
            log_info "Internet connectivity restored successfully"
        else
            log_warn "Internet connectivity may still be broken - check routing manually"
        fi
    else
        log_error "Route restoration failed: $response"
        exit 1
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log_warn "⚠️  UNSAFE TEST SCRIPT - TRAFFIC INTERCEPTION TESTS"
    log_warn "⚠️  This will intercept and log ALL internet traffic"
    log_warn "⚠️  Only run this in a controlled environment"
    log_warn "⚠️  Make sure the server is running with -unsafe flag"
    echo
    
    # Set up cleanup on exit
    setup_cleanup
    
    # Run tests
    check_root
    check_server_unsafe
    wait_for_server
    
    # Create interface first
    log_info "Creating interface for interception test..."
    curl -s -X POST http://localhost:$SERVER_PORT/api/interface/create \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$INTERFACE_NAME\",
            \"address\": \"$INTERFACE_IP\",
            \"netmask\": \"$INTERFACE_NETMASK\",
            \"mtu\": $INTERFACE_MTU
        }" > /dev/null
    
    # Start packet processing
    curl -s -X POST http://localhost:$SERVER_PORT/api/interface/start > /dev/null
    
    # Run unsafe tests
    test_intercept
    test_packet_logging
    
    # Wait a bit for user to see logs
    log_info "Waiting 10 seconds for you to check packet logs..."
    sleep 10
    
    test_restore
    
    log_info "Unsafe tests completed! 🎉"
}

# Run main function
main "$@" 