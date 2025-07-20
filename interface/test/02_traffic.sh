#!/bin/bash

# ThinkPol VPN Interface Traffic Test Script
# This script tests packet processing and traffic logging functionality

set -e

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test_utils.sh"

# =============================================================================
# TRAFFIC TESTS
# =============================================================================

# Test packet processing with ICMP traffic
test_icmp_traffic() {
    log_info "Testing packet processing with ICMP traffic..."
    
    # Create and start interface
    if ! create_interface; then
        log_error "Failed to create interface for ICMP test"
        return 1
    fi
    
    if ! start_interface; then
        log_error "Failed to start interface for ICMP test"
        return 1
    fi
    
    # Wait a moment for interface to be ready
    sleep 2
    
    # Generate ICMP traffic
    generate_icmp_traffic
    
    log_info "Check server logs for packet processing output"
    
    # Stop and delete interface
    if ! stop_interface; then
        log_error "Failed to stop interface for ICMP test"
        return 1
    fi
    
    if ! delete_interface; then
        log_error "Failed to delete interface for ICMP test"
        return 1
    fi
    
    # Small delay to ensure cleanup completes
    sleep 1
}

# Test packet processing with TCP traffic
test_tcp_traffic() {
    log_info "Testing packet processing with TCP traffic..."
    
    # Create and start interface
    if ! create_interface; then
        log_error "Failed to create interface for TCP test"
        return 1
    fi
    
    if ! start_interface; then
        log_error "Failed to start interface for TCP test"
        return 1
    fi
    
    # Wait a moment for interface to be ready
    sleep 2
    
    # Generate TCP traffic
    generate_tcp_traffic
    
    log_info "Check server logs for packet processing output"
    
    # Stop and delete interface
    if ! stop_interface; then
        log_error "Failed to stop interface for TCP test"
        return 1
    fi
    
    if ! delete_interface; then
        log_error "Failed to delete interface for TCP test"
        return 1
    fi
    
    # Small delay to ensure cleanup completes
    sleep 1
}

# Test packet processing with UDP traffic
test_udp_traffic() {
    log_info "Testing packet processing with UDP traffic..."
    
    # Create and start interface
    if ! create_interface; then
        log_error "Failed to create interface for UDP test"
        return 1
    fi
    
    if ! start_interface; then
        log_error "Failed to start interface for UDP test"
        return 1
    fi
    
    # Wait a moment for interface to be ready
    sleep 2
    
    # Generate UDP traffic
    generate_udp_traffic
    
    log_info "Check server logs for packet processing output"
    
    # Stop and delete interface
    if ! stop_interface; then
        log_error "Failed to stop interface for UDP test"
        return 1
    fi
    
    if ! delete_interface; then
        log_error "Failed to delete interface for UDP test"
        return 1
    fi
    
    # Small delay to ensure cleanup completes
    sleep 1
}

# Test packet processing with mixed traffic
test_mixed_traffic() {
    log_info "Testing packet processing with mixed traffic types..."
    
    # Create and start interface
    if ! create_interface; then
        log_error "Failed to create interface for mixed traffic test"
        return 1
    fi
    
    if ! start_interface; then
        log_error "Failed to start interface for mixed traffic test"
        return 1
    fi
    
    # Wait a moment for interface to be ready
    sleep 2
    
    # Generate mixed traffic
    generate_mixed_traffic
    
    log_info "Check server logs for packet processing output"
    
    # Stop and delete interface
    if ! stop_interface; then
        log_error "Failed to stop interface for mixed traffic test"
        return 1
    fi
    
    if ! delete_interface; then
        log_error "Failed to delete interface for mixed traffic test"
        return 1
    fi
    
    # Small delay to ensure cleanup completes
    sleep 1
}

# Test packet logging format
test_packet_logging_format() {
    log_info "Testing packet logging format..."
    
    # Create and start interface
    if ! create_interface; then
        log_error "Failed to create interface for packet logging test"
        return 1
    fi
    
    if ! start_interface; then
        log_error "Failed to start interface for packet logging test"
        return 1
    fi
    
    # Wait a moment for interface to be ready
    sleep 2
    
    log_info "Generating test traffic to verify logging format..."
    
    # Send some test traffic
    generate_icmp_traffic $INTERFACE_IP 1
    
    log_info "✓ Test traffic generated"
    log_info "Expected log format: [PACKET] IPv4: source -> destination (protocol)"
    log_info "Check server logs to verify packet logging format"
    
    # Stop and delete interface
    if ! stop_interface; then
        log_error "Failed to stop interface for packet logging test"
        return 1
    fi
    
    if ! delete_interface; then
        log_error "Failed to delete interface for packet logging test"
        return 1
    fi
    
    # Small delay to ensure cleanup completes
    sleep 1
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Set up cleanup on exit
    setup_cleanup
    
    # SETUP PHASE
    check_root
    check_server
    wait_for_server
    
    log_info "Setup complete! Starting traffic tests..."
    echo ""
    
    # TRAFFIC TESTS
    test_icmp_traffic
    test_tcp_traffic
    test_udp_traffic
    test_mixed_traffic
    test_packet_logging_format
    
    echo ""
    log_info "All traffic tests completed! 🎉"
    log_info "Check the server logs to see packet processing output"
}

# Run main function
main "$@" 