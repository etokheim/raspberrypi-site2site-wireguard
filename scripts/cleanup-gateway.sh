#!/bin/bash

# cleanup-gateway.sh
# Removes VPN Gateway configuration.
# Enhanced with UI improvements and logging.

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOG_DIR/vpn_cleanup.log"
CONFIG_FILE="$ROOT_DIR/vpn-gateway.conf"
LEGACY_CONFIG_1="$ROOT_DIR/gateway.conf"
LEGACY_CONFIG_2="$ROOT_DIR/vpn_gateway.conf"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

remove_auto_updates() {
    {
        export DEBIAN_FRONTEND=noninteractive
        systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
        rm -f /etc/apt/apt.conf.d/51unattended-upgrades-gateway /etc/apt/apt.conf.d/52periodic-gateway
        apt-get purge -y unattended-upgrades >/dev/null 2>&1 || true
        apt-get autoremove -y >/dev/null 2>&1 || true
    } >> "$LOG_FILE" 2>&1
}

remove_software_watchdog() {
    # Remove systemd drop-in overrides for service restart policies
    local services=("dnsmasq" "wg-quick@wg0" "hostapd")
    for svc in "${services[@]}"; do
        local dropin_dir="/etc/systemd/system/${svc}.d"
        if [ -d "$dropin_dir" ]; then
            rm -rf "$dropin_dir" >> "$LOG_FILE" 2>&1 || true
        fi
    done
    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || true
}

remove_hardware_watchdog() {
    # Stop and disable hardware watchdog service
    systemctl disable --now watchdog 2>/dev/null >> "$LOG_FILE" 2>&1 || true
    
    # Restore original watchdog.conf if backup exists
    if [ -f /etc/watchdog.conf.bak_gateway ]; then
        mv /etc/watchdog.conf.bak_gateway /etc/watchdog.conf >> "$LOG_FILE" 2>&1 || true
    fi
}

cleanup_gateway_nat_rules() {
    local lan_iface="$LAN_IFACE"
    local wan_iface="$WAN_IFACE"
    
    # Remove specific forward rules (LAN -> wg0)
    if [ -n "$lan_iface" ]; then
        if iptables -C FORWARD -i "$lan_iface" -o wg0 -j ACCEPT >/dev/null 2>&1; then
            iptables -D FORWARD -i "$lan_iface" -o wg0 -j ACCEPT >> "$LOG_FILE" 2>&1 || true
        fi
        if iptables -C FORWARD -i wg0 -o "$lan_iface" -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
            iptables -D FORWARD -i wg0 -o "$lan_iface" -m state --state RELATED,ESTABLISHED -j ACCEPT >> "$LOG_FILE" 2>&1 || true
        fi
    fi
    
    # Remove specific NAT rules
    if iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE >/dev/null 2>&1; then
        iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE >> "$LOG_FILE" 2>&1 || true
    fi
    if [ -n "$wan_iface" ] && iptables -t nat -C POSTROUTING -o "$wan_iface" -j MASQUERADE >/dev/null 2>&1; then
        iptables -t nat -D POSTROUTING -o "$wan_iface" -j MASQUERADE >> "$LOG_FILE" 2>&1 || true
    fi
}

cleanup_wan_firewall_rules() {
    local wan_iface="$WAN_IFACE"
    local lan_iface="$LAN_IFACE"
    local ssh_port="${SSH_PORT:-22}"
    local wg_port="${WG_LISTEN_PORT:-}"

    if [ -n "$lan_iface" ] && iptables -C INPUT -i "$lan_iface" -j ACCEPT >/dev/null 2>&1; then
        iptables -D INPUT -i "$lan_iface" -j ACCEPT >> "$LOG_FILE" 2>&1 || true
    fi
    if [ -n "$wan_iface" ]; then
        if iptables -C INPUT -i "$wan_iface" -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
            iptables -D INPUT -i "$wan_iface" -m state --state RELATED,ESTABLISHED -j ACCEPT >> "$LOG_FILE" 2>&1 || true
        fi
        if iptables -C INPUT -i "$wan_iface" -p tcp --dport "$ssh_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -D INPUT -i "$wan_iface" -p tcp --dport "$ssh_port" -j ACCEPT >> "$LOG_FILE" 2>&1 || true
        fi
        if [ -n "$wg_port" ] && iptables -C INPUT -i "$wan_iface" -p udp --dport "$wg_port" -j ACCEPT >/dev/null 2>&1; then
            iptables -D INPUT -i "$wan_iface" -p udp --dport "$wg_port" -j ACCEPT >> "$LOG_FILE" 2>&1 || true
        fi
        if iptables -C INPUT -i "$wan_iface" -j DROP >/dev/null 2>&1; then
            iptables -D INPUT -i "$wan_iface" -j DROP >> "$LOG_FILE" 2>&1 || true
        fi
    fi
}

init_log() {
    mkdir -p "$LOG_DIR"
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
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
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
    NONINTERACTIVE="${NONINTERACTIVE:-false}"
    
    # Load config if available to identify LAN interface
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$LEGACY_CONFIG_1" ]; then
            mv "$LEGACY_CONFIG_1" "$CONFIG_FILE"
        elif [ -f "$LEGACY_CONFIG_2" ]; then
            mv "$LEGACY_CONFIG_2" "$CONFIG_FILE"
        fi
    fi
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        echo "Loaded configuration from $CONFIG_FILE" >> "$LOG_FILE"
    fi
    
    print_header

    # Planned changes summary
    local box_w=95
    local border_inner=95
    local border_line
    border_line=$(printf '═%.0s' $(seq 1 $border_inner))

    echo "╔${border_line}╗"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "📝 Planned changes (cleanup)"
    echo "╠${border_line}╣"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Stop WireGuard and remove wg0 config"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Stop/disable DHCP (dnsmasq)"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Stop/disable hostapd (if running)"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Flush firewall/NAT and reset IP forwarding"
    if [ "${FIREWALL_ENABLED:-true}" = "true" ]; then
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Remove WAN firewall rules"
    else
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• WAN firewall rules were disabled (skip removal)"
    fi
    if [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ]; then
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Disable and remove unattended-upgrades config"
    else
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Automatic updates not enabled (skip removal)"
    fi
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Restore network manager settings (nmcli/dhcpcd) to DHCP"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Remove software watchdog (systemd drop-in overrides)"
    if [ "${WATCHDOG_ENABLED:-false}" = "true" ]; then
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Remove hardware watchdog configuration"
    else
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Hardware watchdog not enabled (skip removal)"
    fi
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Restore backup configs (dnsmasq.conf, hostapd.conf if applicable)"
    echo "╚${border_line}╝"
    echo ""
    if [ "${NONINTERACTIVE:-false}" = "true" ]; then
        echo "Non-interactive mode: proceeding with cleanup."
    else
        echo -ne "Proceed with cleanup/restore? [Y/n]: "
        read -r proceed_choice
        if [[ "$proceed_choice" =~ ^[Nn]$ ]]; then
            echo "Aborting cleanup by user request."
            exit 1
        fi
    fi

    run_step "Stopping WireGuard Service" "systemctl stop wg-quick@wg0; systemctl disable wg-quick@wg0"
    
    # Also try manual down in case it wasn't a service
    run_step "Ensuring WireGuard Interface Down" "if ip link show wg0 >/dev/null 2>&1; then wg-quick down wg0; fi"

    run_step "Stopping DHCP Server (dnsmasq)" "systemctl stop dnsmasq; systemctl disable dnsmasq"

    # Stop hostapd if it was installed/active
    if systemctl is-active --quiet hostapd; then
        run_step "Stopping Access Point (hostapd)" "systemctl stop hostapd; systemctl disable hostapd"
    fi

    if [ "${FIREWALL_ENABLED:-true}" = "true" ]; then
        run_step "Removing WAN firewall rules" "cleanup_wan_firewall_rules"
    else
        echo "Skipping WAN firewall cleanup (disabled in config)" >> "$LOG_FILE"
    fi

    run_step "Removing gateway NAT/forward rules" "cleanup_gateway_nat_rules"

    run_step "Disabling IP Forwarding" "rm -f /etc/sysctl.d/99-vpn-gateway.conf && sysctl --system"

    if [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ]; then
        run_step "Removing automatic updates configuration" "remove_auto_updates"
    fi

    run_step "Removing software watchdog configuration" "remove_software_watchdog"

    if [ "${WATCHDOG_ENABLED:-false}" = "true" ]; then
        run_step "Removing hardware watchdog configuration" "remove_hardware_watchdog"
    fi

    if command -v netfilter-persistent >/dev/null 2>&1; then
        run_step "Saving empty firewall rules to persistence" "netfilter-persistent save"
    fi

    echo -ne "⏳ ${CYAN}Restoring Network Configuration...${NC} "
    {
        # Flush static IP from LAN interface (especially for wireless where we bypassed nmcli)
        if [ -n "$LAN_IFACE" ]; then
            echo "Flushing IP addresses from $LAN_IFACE..." >> "$LOG_FILE"
            ip addr flush dev "$LAN_IFACE" >> "$LOG_FILE" 2>&1 || true
        fi

        # NetworkManager Restore
        if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
             if [ -n "$LAN_IFACE" ]; then
                 # We know the interface! Try to find the connection we modified.
                 # Our setup script creates/uses "Wired connection $LAN_IFACE" or similar.
                 # Let's try to find connection by device name.
                 CON_NAME=$(nmcli -t -f NAME,DEVICE connection show | grep ":$LAN_IFACE$" | cut -d: -f1 | head -n1)
                 
                 if [ -n "$CON_NAME" ]; then
                     echo "Resetting NetworkManager connection '$CON_NAME' to auto..." >> "$LOG_FILE"
                     nmcli con modify "$CON_NAME" ipv4.method auto >> "$LOG_FILE" 2>&1
                     # Re-apply
                     nmcli con up "$CON_NAME" >> "$LOG_FILE" 2>&1
                 else
                     echo "  [WARNING] Could not find NetworkManager connection for interface $LAN_IFACE" >> "$LOG_FILE"
                 fi
             else
                 echo "  [WARNING] LAN Interface unknown (no config file). Cannot automatically revert static IP." >> "$LOG_FILE"
                 echo "  Please run 'nmcli con modify <conn_name> ipv4.method auto' manually." >> "$LOG_FILE"
             fi
             
        elif [ -f /etc/dhcpcd.conf ]; then
            sed -i '/# VPN-GATEWAY-START/,/# VPN-GATEWAY-END/d' /etc/dhcpcd.conf
            systemctl restart dhcpcd >> "$LOG_FILE" 2>&1
        fi
    } && echo -e " [${GREEN}DONE${NC}]" || echo -e " [${RED}FAIL${NC}]"

    # Restore backup configuration files
    echo -ne "⏳ ${CYAN}Restoring backup configuration files...${NC} "
    {
        # Restore dnsmasq.conf backup
        if [ -f /etc/dnsmasq.conf.bak ]; then
            echo "Restoring /etc/dnsmasq.conf from backup..." >> "$LOG_FILE"
            mv /etc/dnsmasq.conf.bak /etc/dnsmasq.conf >> "$LOG_FILE" 2>&1 || true
        fi

        # Remove hostapd configuration if wireless was used
        if [ "${IS_WIRELESS:-false}" = "true" ]; then
            echo "Removing hostapd configuration..." >> "$LOG_FILE"
            rm -f /etc/hostapd/hostapd.conf >> "$LOG_FILE" 2>&1 || true
            # Restore /etc/default/hostapd to default
            if [ -f /etc/default/hostapd ]; then
                sed -i 's|DAEMON_CONF="/etc/hostapd/hostapd.conf"|#DAEMON_CONF=""|' /etc/default/hostapd >> "$LOG_FILE" 2>&1 || true
            fi
        fi

        # Remove WireGuard configuration
        if [ -f /etc/wireguard/wg0.conf ]; then
            echo "Removing /etc/wireguard/wg0.conf..." >> "$LOG_FILE"
            rm -f /etc/wireguard/wg0.conf >> "$LOG_FILE" 2>&1 || true
        fi
    } && echo -e " [${GREEN}DONE${NC}]" || echo -e " [${RED}FAIL${NC}]"

    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║               ✔ Restore Complete!                         ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "The Pi should now be back to its original state."
    echo -e "See ${YELLOW}$LOG_FILE${NC} for details."
    
    if [ -f "$CONFIG_FILE" ]; then
        echo ""
        if [ "${NONINTERACTIVE:-false}" = "true" ]; then
            echo -e "   [${YELLOW}Kept${NC}] $CONFIG_FILE (non-interactive mode; not deleting)"
        else
            echo -ne "❓ ${CYAN}Do you want to delete the configuration file ($CONFIG_FILE)? [y/N]${NC} "
            read -r delete_conf
            if [[ "$delete_conf" =~ ^[Yy]$ ]]; then
                rm "$CONFIG_FILE"
                echo -e "   [${GREEN}Deleted${NC}] $CONFIG_FILE"
            else
                echo -e "   [${YELLOW}Kept${NC}] $CONFIG_FILE (Useful for re-running setup)"
            fi
        fi
    fi
}

main
