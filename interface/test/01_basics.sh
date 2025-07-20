#!/bin/bash

# ThinkPol VPN Interface Basic Test Script
# This script tests the core TUN interface management functionality

set -e

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test_utils.sh"

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
    
    log_info "Setup complete! Starting basic tests..."
    echo ""
    
    # BASIC TESTS
    test_health
    test_no_interface_operations
    test_interface_lifecycle
    test_error_handling
    
    echo ""
    log_info "All basic tests passed! 🎉"
}

# Run main function
main "$@" 