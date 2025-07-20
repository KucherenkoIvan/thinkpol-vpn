#!/bin/bash

# ThinkPol VPN Interface Test Runner
# This script finds and runs all test files that start with two digits in numerical order

set -e

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

log_header() {
    echo -e "${BLUE}[TEST RUNNER]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PORT=8080

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    log_header "✓ Root privileges confirmed"
}

# Check if server is running
check_server() {
    if ! curl -s http://localhost:$SERVER_PORT/health > /dev/null; then
        log_error "Server is not running on port $SERVER_PORT"
        log_info "Start the server with: sudo go run cmd/main.go -port $SERVER_PORT"
        exit 1
    fi
    log_header "✓ Server is running on port $SERVER_PORT"
}

# Wait for server to be ready
wait_for_server() {
    log_header "Waiting for server to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:$SERVER_PORT/health > /dev/null; then
            log_header "✓ Server is ready!"
            return 0
        fi
        sleep 1
    done
    log_error "Server did not become ready in time"
    exit 1
}

# Find test files that start with two digits
find_test_files() {
    log_header "Finding test files..."
    
    # Find all .sh files that start with two digits
    test_files=($(find "$SCRIPT_DIR" -maxdepth 1 -name "[0-9][0-9]_*.sh" -type f | sort))
    
    if [ ${#test_files[@]} -eq 0 ]; then
        log_error "No test files found matching pattern [0-9][0-9]_*.sh"
        exit 1
    fi
    
    log_info "Found ${#test_files[@]} test file(s):"
    for file in "${test_files[@]}"; do
        filename=$(basename "$file")
        log_info "  - $filename"
    done
    
    echo ""
}

# Run a single test file
run_test_file() {
    local test_file="$1"
    local filename=$(basename "$test_file")
    
    log_header "Running test: $filename"
    echo "=================================================="
    
    # Check if file is executable
    if [ ! -x "$test_file" ]; then
        log_warn "Making $filename executable..."
        chmod +x "$test_file"
    fi
    
    # Run the test file
    if "$test_file"; then
        log_info "✓ $filename completed successfully"
        echo "=================================================="
        echo ""
        return 0
    else
        log_error "✗ $filename failed with exit code $?"
        echo "=================================================="
        echo ""
        return 1
    fi
}

# Run all test files
run_all_tests() {
    local failed_tests=()
    local passed_tests=()
    local total_tests=${#test_files[@]}
    local current_test=0
    
    log_header "Starting test execution..."
    echo ""
    
    for test_file in "${test_files[@]}"; do
        current_test=$((current_test + 1))
        filename=$(basename "$test_file")
        
        log_header "Test $current_test/$total_tests: $filename"
        
        if run_test_file "$test_file"; then
            passed_tests+=("$filename")
        else
            failed_tests+=("$filename")
        fi
        
        # Small delay between tests
        sleep 1
    done
    
    # Print summary
    echo ""
    log_header "Test Execution Summary"
    echo "=================================================="
    log_info "Total tests: $total_tests"
    log_info "Passed: ${#passed_tests[@]}"
    log_error "Failed: ${#failed_tests[@]}"
    
    if [ ${#passed_tests[@]} -gt 0 ]; then
        echo ""
        log_info "Passed tests:"
        for test in "${passed_tests[@]}"; do
            log_info "  ✓ $test"
        done
    fi
    
    if [ ${#failed_tests[@]} -gt 0 ]; then
        echo ""
        log_error "Failed tests:"
        for test in "${failed_tests[@]}"; do
            log_error "  ✗ $test"
        done
    fi
    
    echo "=================================================="
    
    # Return appropriate exit code
    if [ ${#failed_tests[@]} -eq 0 ]; then
        log_info "All tests passed! 🎉"
        return 0
    else
        log_error "Some tests failed! ❌"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_header "Cleaning up..."
    # Try to stop and delete interface if it exists
    curl -s -X POST http://localhost:$SERVER_PORT/api/interface/stop > /dev/null 2>&1 || true
    curl -s -X DELETE http://localhost:$SERVER_PORT/api/interface/delete > /dev/null 2>&1 || true
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -l, --list     List all available test files without running them"
    echo "  -s, --server   Skip server check (assume server is already running)"
    echo ""
    echo "This script will:"
    echo "  1. Find all test files matching pattern [0-9][0-9]_*.sh"
    echo "  2. Run them in numerical order"
    echo "  3. Provide a summary of results"
    echo ""
    echo "Example:"
    echo "  sudo $0                    # Run all tests"
    echo "  sudo $0 --list             # List available tests"
    echo "  sudo $0 --server           # Skip server check"
}

# Parse command line arguments
parse_args() {
    local list_only=false
    local skip_server_check=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -l|--list)
                list_only=true
                shift
                ;;
            -s|--server)
                skip_server_check=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # If list only, just show the files and exit
    if [ "$list_only" = true ]; then
        find_test_files
        log_header "Available test files (not running):"
        for file in "${test_files[@]}"; do
            filename=$(basename "$file")
            log_info "  - $filename"
        done
        exit 0
    fi
    
    # Set global flag for server check
    SKIP_SERVER_CHECK=$skip_server_check
}

# Main function
main() {
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Parse command line arguments
    parse_args "$@"
    
    log_header "ThinkPol VPN Interface Test Runner"
    echo "=================================================="
    
    # Setup phase
    check_root
    
    if [ "$SKIP_SERVER_CHECK" != true ]; then
        check_server
        wait_for_server
    else
        log_warn "Skipping server check (--server flag used)"
    fi
    
    # Find test files
    find_test_files
    
    # Run all tests
    run_all_tests
}

# Run main function
main "$@" 