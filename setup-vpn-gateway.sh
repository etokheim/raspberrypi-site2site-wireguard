#!/bin/bash

# setup-vpn-gateway.sh
# Configures Raspberry Pi as a VPN Gateway with WireGuard and dnsmasq.
# Enhanced with UI improvements and logging.

set -o pipefail

# --- Configuration & Globals ---
LOG_FILE="vpn_setup.log"
TERM_WIDTH=$(tput cols)

# --- Colors & Styles ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- UI Functions ---

# Initialize Log
init_log() {
    echo "--- VPN Gateway Setup Log Started: $(date) ---" > "$LOG_FILE"
}

# Print Header
print_header() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           Raspberry Pi VPN Gateway Setup                   ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "📄 Log file: ${YELLOW}$LOG_FILE${NC}"
    echo ""
}

# Print Status Message
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to run a command with a spinner and logging
# Usage: run_step "Description of task" command_to_run arg1 arg2 ...
run_step() {
    local msg="$1"
    shift
    local cmd="$@"
    
    # Calculate padding for alignment
    local msg_len=${#msg}
    local pad_len=$((TERM_WIDTH - msg_len - 15))
    [ $pad_len -lt 1 ] && pad_len=1
    
    echo -ne "⏳ ${CYAN}${msg}${NC} "
    
    # Run the command in background, redirecting output to log
    {
        echo "[$msg] Executing: $cmd" >> "$LOG_FILE"
        eval "$cmd" >> "$LOG_FILE" 2>&1
    } & 
    local pid=$!
    
    # Spinner loop
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
    
    # Clear spinner
    printf "       \b\b\b\b\b\b\b"

    if [ $exit_code -eq 0 ]; then
        echo -e "[${GREEN}DONE${NC}]"
    else
        echo -e "[${RED}FAIL${NC}]"
        error "Task failed. Check $LOG_FILE for details."
        exit 1
    fi
}

# --- Main Logic ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo ./setup-vpn-gateway.sh)"
        exit 1
    fi
}

# Function to list network interfaces
get_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"
}

# Function to prompt for interface selection
select_interface() {
    local prompt_text="$1"
    local interfaces=$(get_interfaces)
    local chosen_iface=""

    echo -e "${BOLD}$prompt_text${NC}"
    PS3="👉 Select interface number: "
    select iface in $interfaces; do
        if [ -n "$iface" ]; then
            chosen_iface="$iface"
            break
        else
            warn "Invalid selection. Please try again."
        fi
    done
    echo "$chosen_iface"
}

get_wg_config() {
    while true; do
        echo -ne "📂 Enter path to WireGuard peer config file (e.g., /home/pi/wg0.conf): "
        read -e wg_conf_path
        if [ -f "$wg_conf_path" ]; then
            echo "$wg_conf_path"
            break
        else
            warn "File not found: $wg_conf_path. Please try again."
        fi
    done
}

get_ip_range() {
    echo -ne "🌐 Enter LAN IP range (CIDR) [default: ${YELLOW}10.10.10.0/24${NC}]: "
    read -e lan_cidr
    if [ -z "$lan_cidr" ]; then
        lan_cidr="10.10.10.0/24"
    fi
    echo "$lan_cidr"
}

main() {
    init_log
    check_root
    print_header

    info "Checking System Dependencies..."
    echo -ne "❓ ${YELLOW}Do you want to install necessary packages (wireguard, dnsmasq, iptables)? [Y/n]${NC} "
    read -r install_choice
    if [[ "$install_choice" =~ ^[Nn]$ ]]; then
        error "Package installation is required to proceed. Exiting."
        exit 1
    else
        run_step "Updating package list" "apt-get update"
        run_step "Installing WireGuard, dnsmasq, iptables" "apt-get install -y wireguard dnsmasq qrencode iptables"
    fi

    echo ""
    info "Network Interface Configuration"
    echo "------------------------------------------------"
    WAN_IFACE=$(select_interface "Select the WAN interface (Internet connection):")
    success "WAN: $WAN_IFACE"
    echo ""
    LAN_IFACE=$(select_interface "Select the LAN interface (Access Point connection):")
    success "LAN: $LAN_IFACE"
    echo ""

    if [ "$WAN_IFACE" == "$LAN_IFACE" ]; then
        error "WAN and LAN interfaces cannot be the same."
        exit 1
    fi

    LAN_CIDR=$(get_ip_range)
    LAN_IP=$(echo "$LAN_CIDR" | sed 's/\.0\/24$/.1/')
    
    SUBNET_BASE=$(echo "$LAN_CIDR" | cut -d'/' -f1)
    PREFIX=$(echo "$SUBNET_BASE" | cut -d'.' -f1-3)
    LAN_GATEWAY="$PREFIX.1"
    DHCP_START="$PREFIX.10"
    DHCP_END="$PREFIX.250"

    info "Configuration Details:"
    echo -e "   • Subnet:  ${CYAN}$LAN_CIDR${NC}"
    echo -e "   • Gateway: ${CYAN}$LAN_GATEWAY${NC}"
    echo -e "   • DHCP:    ${CYAN}$DHCP_START - $DHCP_END${NC}"
    echo ""

    WG_CONF_SRC=$(get_wg_config)
    WG_CONF_DEST="/etc/wireguard/wg0.conf"

    echo ""
    run_step "Installing WireGuard config" "cp \"$WG_CONF_SRC\" \"$WG_CONF_DEST\" && chmod 600 \"$WG_CONF_DEST\""

    run_step "Enabling IP Forwarding" "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn-gateway.conf && sysctl -p /etc/sysctl.d/99-vpn-gateway.conf"

    # Configure static IP for LAN interface
    # We construct the command carefully to pass to run_step
    # Since this involves complex multi-line writes, we'll write a temporary helper script or use a function.
    # Simpler: Just do the logic here but log it.
    
    echo -ne "⏳ ${CYAN}Configuring Network Interfaces...${NC} "
    {
        echo "[Configuring Network Interfaces]" >> "$LOG_FILE"
        if [ -f /etc/dhcpcd.conf ]; then
             sed -i '/# VPN-GATEWAY-START/,/# VPN-GATEWAY-END/d' /etc/dhcpcd.conf
             {
                echo "# VPN-GATEWAY-START"
                echo "interface $LAN_IFACE"
                echo "static ip_address=$LAN_GATEWAY/24"
                echo "nohook wpa_supplicant"
                echo "# VPN-GATEWAY-END"
            } >> /etc/dhcpcd.conf
            systemctl restart dhcpcd >> "$LOG_FILE" 2>&1
        else
            ip addr add "$LAN_GATEWAY/24" dev "$LAN_IFACE" >> "$LOG_FILE" 2>&1
        fi
    } || { echo -e "[${RED}FAIL${NC}]"; exit 1; }
    echo -e "[${GREEN}DONE${NC}]"

    # Configure dnsmasq
    echo -ne "⏳ ${CYAN}Configuring DHCP (dnsmasq)...${NC} "
    {
        mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null || true
        cat > /etc/dnsmasq.conf <<EOF
interface=$LAN_IFACE
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h
dhcp-option=option:dns-server,$LAN_GATEWAY
dhcp-option=option:router,$LAN_GATEWAY
bind-interfaces
EOF
        systemctl restart dnsmasq >> "$LOG_FILE" 2>&1
        systemctl enable dnsmasq >> "$LOG_FILE" 2>&1
    } || { echo -e "[${RED}FAIL${NC}]"; exit 1; }
    echo -e "[${GREEN}DONE${NC}]"


    run_step "Configuring Firewall / NAT Rules" "bash -c \"
        if ! grep -q '\[Interface\]' '$WG_CONF_DEST'; then exit 1; fi;
        POST_UP='PostUp = iptables -A FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE; iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE';
        POST_DOWN='PostDown = iptables -D FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE; iptables -t nat -D POSTROUTING -o $WAN_IFACE -j MASQUERADE';
        awk -v up=\\\"\$POST_UP\\\" -v down=\\\"\$POST_DOWN\\\" '/\[Interface\]/ { print; print up; print down; next } 1' '$WG_CONF_DEST' > '${WG_CONF_DEST}.tmp' && mv '${WG_CONF_DEST}.tmp' '$WG_CONF_DEST'
    \""

    run_step "Starting WireGuard VPN" "wg-quick up wg0 && systemctl enable wg-quick@wg0"

    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  🎉 Setup Complete! 🎉                     ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    success "Status:"
    echo -e "   • WAN Interface: ${BOLD}$WAN_IFACE${NC}"
    echo -e "   • LAN Interface: ${BOLD}$LAN_IFACE${NC} (Gateway: $LAN_GATEWAY)"
    echo -e "   • VPN Interface: ${BOLD}wg0${NC}"
    echo ""
    info "Setup log saved to: $LOG_FILE"
}

main
