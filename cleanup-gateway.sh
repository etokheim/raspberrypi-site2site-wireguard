#!/bin/bash

# cleanup-gateway.sh
# Removes VPN Gateway configuration.
# Enhanced with UI improvements and logging.

set -o pipefail

LOG_FILE="vpn_cleanup.log"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

init_log() {
    echo "--- VPN Gateway Cleanup Log Started: $(date) ---" > "$LOG_FILE"
}

print_header() {
    clear
    echo -e "${RED}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           VPN Gateway Cleanup / Restore                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "📄 Log file: ${YELLOW}$LOG_FILE${NC}"
    echo ""
}

run_step() {
    local msg="$1"
    shift
    local cmd="$@"
    
    echo -ne "⏳ ${CYAN}${msg}${NC} "
    
    {
        echo "[$msg] Executing: $cmd" >> "$LOG_FILE"
        eval "$cmd" >> "$LOG_FILE" 2>&1
    } & 
    local pid=$!
    
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    wait $pid
    local exit_code=$?
    printf "       \b\b\b\b\b\b\b"

    if [ $exit_code -eq 0 ]; then
        echo -e "[${GREEN}DONE${NC}]"
    else
        echo -e "[${RED}FAIL${NC}]" # Don't exit on fail in cleanup, try to continue
        echo "Error in: $msg. Check log." >> "$LOG_FILE"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi
}

main() {
    init_log
    check_root
    print_header

    echo -e "${YELLOW}⚠️  This will remove WireGuard configuration and network settings.${NC}"
    echo -e "   Press [ENTER] to continue or Ctrl+C to cancel."
    read

    run_step "Stopping WireGuard Service" "systemctl stop wg-quick@wg0; systemctl disable wg-quick@wg0"
    
    # Also try manual down in case it wasn't a service
    run_step "Ensuring WireGuard Interface Down" "if ip link show wg0 >/dev/null 2>&1; then wg-quick down wg0; fi"

    run_step "Stopping DHCP Server (dnsmasq)" "systemctl stop dnsmasq; systemctl disable dnsmasq"

    # Stop hostapd if it was installed/active
    if systemctl is-active --quiet hostapd; then
        run_step "Stopping Access Point (hostapd)" "systemctl stop hostapd; systemctl disable hostapd"
    fi

    run_step "Flushing Firewall Rules" "iptables -t nat -F; iptables -F FORWARD; iptables -P FORWARD ACCEPT"

    run_step "Disabling IP Forwarding" "rm -f /etc/sysctl.d/99-vpn-gateway.conf && sysctl --system"

    echo -ne "⏳ ${CYAN}Restoring Network Configuration...${NC} "
    {
        if [ -f /etc/dhcpcd.conf ]; then
            sed -i '/# VPN-GATEWAY-START/,/# VPN-GATEWAY-END/d' /etc/dhcpcd.conf
        fi
        systemctl restart dhcpcd >> "$LOG_FILE" 2>&1
    } && echo -e " [${GREEN}DONE${NC}]" || echo -e " [${RED}FAIL${NC}]"

    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║               ✅ Restore Complete!                         ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "The Pi should now be back to its original state."
    echo -e "See ${YELLOW}$LOG_FILE${NC} for details."
}

main
