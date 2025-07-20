#!/bin/bash

# ThinkPol VPN Interface Repair Script
# Cleans up leftover interfaces, routes, and processes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Kill VPN interface processes
kill_processes() {
    log "Looking for VPN interface processes..."
    
    # Find processes by name
    local processes=$(pgrep -f "vpn-interface\|go.*main.go" 2>/dev/null || true)
    
    if [[ -n "$processes" ]]; then
        warn "Found running processes: $processes"
        echo "$processes" | while read -r pid; do
            log "Killing process $pid..."
            kill -TERM "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                warn "Process $pid still running, force killing..."
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done
        success "Processes killed"
    else
        log "No VPN interface processes found"
    fi
}

# Clean up TUN interfaces
cleanup_interfaces() {
    log "Looking for TUN interfaces..."
    
    # macOS uses utun interfaces
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # Look for both system utun interfaces and our custom thinkpol interfaces
        local interfaces=$(ifconfig | grep -E "^(utun[0-9]+|thinkpol[0-9]+):" | awk '{print $1}' | sed 's/://')
        
        if [[ -n "$interfaces" ]]; then
            warn "Found TUN interfaces: $interfaces"
            echo "$interfaces" | while read -r iface; do
                log "Removing interface $iface..."
                
                # First try to bring the interface down
                ifconfig "$iface" down 2>/dev/null || true
                sleep 1
                
                # Then try to destroy it
                if ifconfig "$iface" destroy 2>/dev/null; then
                    log "Successfully destroyed interface $iface"
                else
                    warn "Could not destroy interface $iface (may already be down)"
                    
                    # Try alternative cleanup methods
                    if ifconfig "$iface" 2>/dev/null | grep -q "UP"; then
                        warn "Interface $iface is still UP, trying force down..."
                        ifconfig "$iface" down 2>/dev/null || true
                    fi
                fi
            done
            success "TUN interface cleanup completed"
        else
            log "No TUN interfaces found"
        fi
    
    # Linux uses tun/tap interfaces
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Look for both system tun/tap interfaces and our custom thinkpol interfaces
        local interfaces=$(ip link show | grep -E "tun[0-9]+|tap[0-9]+|thinkpol[0-9]+" | awk -F': ' '{print $2}' | awk '{print $1}')
        
        if [[ -n "$interfaces" ]]; then
            warn "Found TUN/TAP interfaces: $interfaces"
            echo "$interfaces" | while read -r iface; do
                log "Removing interface $iface..."
                
                # First bring interface down
                ip link set "$iface" down 2>/dev/null || true
                sleep 1
                
                # Then delete it
                if ip link delete "$iface" 2>/dev/null; then
                    log "Successfully deleted interface $iface"
                else
                    warn "Could not delete interface $iface (may already be down)"
                fi
            done
            success "TUN/TAP interface cleanup completed"
        else
            log "No TUN/TAP interfaces found"
        fi
    fi
}

# Clean up routes
cleanup_routes() {
    log "Checking for modified routes..."
    
    # Look for routes that might have been added by the VPN interface
    # This is a conservative approach - we'll only remove routes that look suspicious
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS route cleanup
        local suspicious_routes=$(netstat -rn | grep -E "utun[0-9]+|thinkpol[0-9]+" | awk '{print $1, $2}' || true)
        
        if [[ -n "$suspicious_routes" ]]; then
            warn "Found routes through TUN interfaces:"
            echo "$suspicious_routes"
            echo "$suspicious_routes" | while read -r dest gateway; do
                if [[ "$dest" == "default" ]]; then
                    log "Removing default route through $gateway..."
                    route delete default "$gateway" 2>/dev/null || true
                else
                    log "Removing route to $dest through $gateway..."
                    route delete "$dest" "$gateway" 2>/dev/null || true
                fi
            done
            success "Suspicious routes removed"
        else
            log "No suspicious routes found"
        fi
    
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux route cleanup
        local suspicious_routes=$(ip route show | grep -E "tun[0-9]+|tap[0-9]+|thinkpol[0-9]+" || true)
        
        if [[ -n "$suspicious_routes" ]]; then
            warn "Found routes through TUN/TAP interfaces:"
            echo "$suspicious_routes"
            echo "$suspicious_routes" | while read -r route; do
                log "Removing route: $route"
                ip route del $route 2>/dev/null || true
            done
            success "Suspicious routes removed"
        else
            log "No suspicious routes found"
        fi
    fi
}

# Clean up log files
cleanup_logs() {
    log "Cleaning up log files..."
    
    if [[ -d "logs" ]]; then
        log "Removing logs directory..."
        rm -rf logs/
        success "Log files cleaned up"
    else
        log "No logs directory found"
    fi
}

# Reset network configuration
reset_network() {
    log "Resetting network configuration..."
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS network reset
        log "Flushing DNS cache..."
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        
        log "Restarting network services..."
        sudo launchctl unload /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist 2>/dev/null || true
        sudo launchctl load /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist 2>/dev/null || true
        
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux network reset
        log "Restarting network services..."
        systemctl restart NetworkManager 2>/dev/null || true
        systemctl restart systemd-resolved 2>/dev/null || true
    fi
    
    success "Network configuration reset"
}

# Show current status
show_status() {
    log "Current system status:"
    echo
    
    log "Active processes:"
    pgrep -f "vpn-interface\|go.*main.go" 2>/dev/null || echo "  None found"
    echo
    
    log "Network interfaces:"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        ifconfig | grep -E "utun[0-9]+|thinkpol[0-9]+" || echo "  No TUN interfaces found"
    else
        ip link show | grep -E "tun[0-9]+|tap[0-9]+|thinkpol[0-9]+" || echo "  No TUN/TAP interfaces found"
    fi
    echo
    
    log "Routing table:"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        netstat -rn | head -20
    else
        ip route show | head -20
    fi
    echo
}

# Main repair function
repair() {
    log "Starting ThinkPol VPN Interface repair..."
    echo
    
    check_root
    
    # Kill processes first
    kill_processes
    echo
    
    # Clean up interfaces
    cleanup_interfaces
    echo
    
    # Clean up routes
    cleanup_routes
    echo
    
    # Reset network if requested
    if [[ "$1" == "--reset-network" ]]; then
        reset_network
        echo
    fi
    
    # Clean up logs
    cleanup_logs
    echo
    
    success "Repair completed!"
    echo
    
    # Show final status
    show_status
}

# Help function
show_help() {
    echo "ThinkPol VPN Interface Repair Script"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --reset-network    Also reset network configuration (use with caution)"
    echo "  --status           Show current system status only"
    echo "  --help             Show this help message"
    echo
    echo "Examples:"
    echo "  sudo $0                    # Basic repair"
    echo "  sudo $0 --reset-network    # Repair + network reset"
    echo "  sudo $0 --status           # Show status only"
    echo
    echo "This script will:"
    echo "  1. Kill any running VPN interface processes"
    echo "  2. Remove leftover TUN/TAP interfaces"
    echo "  3. Clean up suspicious routes"
    echo "  4. Remove log files"
    echo "  5. Optionally reset network configuration"
}

# Main script logic
case "${1:-}" in
    --help|-h)
        show_help
        exit 0
        ;;
    --status)
        show_status
        exit 0
        ;;
    --reset-network)
        repair "$1"
        ;;
    "")
        repair
        ;;
    *)
        error "Unknown option: $1"
        echo
        show_help
        exit 1
        ;;
esac 