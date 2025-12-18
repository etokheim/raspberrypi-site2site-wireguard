#!/bin/bash

# setup-vpn-gateway.sh
# Configures Raspberry Pi as a VPN Gateway with WireGuard and dnsmasq.
# Enhanced with UI improvements and logging.

set -o pipefail

# --- Configuration & Globals ---
LOG_FILE="vpn_setup.log"
CONFIG_FILE="vpn_gateway.conf"
TERM_WIDTH=$(tput cols)

# --- Configuration Loading ---
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
}

save_config_var() {
    local var_name="$1"
    local var_value="$2"
    
    # Create file if not exists
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "# VPN Gateway Configuration" > "$CONFIG_FILE"
        echo "# Generated on $(date)" >> "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    fi
    
    # Check if var exists in file
    if grep -q "^$var_name=" "$CONFIG_FILE"; then
        # Update existing line (using a temp file to avoid issues)
        # Using simple sed with delimiter that likely won't appear in values (pipe |)
        # Escape slashes in value for safety if using paths
        local escaped_value=$(echo "$var_value" | sed 's/|/\\|/g') 
        sed -i "s|^$var_name=.*|$var_name=\"$escaped_value\"|" "$CONFIG_FILE"
    else
        # Append new var
        echo "$var_name=\"$var_value\"" >> "$CONFIG_FILE"
    fi
}

save_full_config() {
    # Legacy function kept for final save, but now redundant with incremental saves
    # We'll just update the timestamp header if we want, or do nothing.
    :
}

# --- Colors & Styles ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- UI Functions ---

# Trap Function for Ctrl+C
cleanup_on_interrupt() {
    # Disable the trap to prevent recursion (Ctrl+C again will kill immediately)
    trap - SIGINT
    
    # Reset terminal state in case a read was interrupted
    stty sane

    echo ""
    echo -e "${RED}${BOLD}🚨 Setup Interrupted!${NC}"
    echo -e "${YELLOW}The system might be in an inconsistent state.${NC}"
    echo ""
    
    # Use read without timeout
    echo -ne "❓ ${CYAN}Do you want to run the cleanup script to restore original settings? [Y/n]${NC} "
    read -r cleanup_choice
    
    if [[ ! "$cleanup_choice" =~ ^[Nn]$ ]]; then
        info "\nRunning cleanup script..."
        if [ -f "./cleanup-gateway.sh" ]; then
            ./cleanup-gateway.sh
        else
            error "Cleanup script not found! Please run cleanup-gateway.sh manually."
        fi
    else
        warn "\nExiting without cleanup. You may need to manually fix network configurations."
    fi
    exit 1
}

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
    local default_iface="$2"
    local interfaces=$(get_interfaces)
    local chosen_iface=""

    # Print UI to stderr so it doesn't get captured in the variable
    echo -e "${BOLD}$prompt_text${NC}" >&2
    if [ -n "$default_iface" ]; then
        echo -e "   (Default from config: ${YELLOW}$default_iface${NC})" >&2
    fi
    
    PS3="👉 Select interface number: "
    select iface in $interfaces; do
        if [ -n "$iface" ]; then
            chosen_iface="$iface"
            break
        else
            warn "Invalid selection. Please try again." >&2
        fi
    done
    
    # Only stdout the result
    echo "$chosen_iface"
}

get_wg_config() {
    # Pre-fill default from config if available
    local default_path="${WG_CONF_PATH:-}"
    local prompt_msg="📂 Enter path to WireGuard peer config file"
    if [ -n "$default_path" ]; then
        prompt_msg="$prompt_msg [default: ${YELLOW}$default_path${NC}]"
    fi
    
    while true; do
        # Use echo -ne for color support in default value display
        echo -ne "$prompt_msg: "
        read -r input_path
        
        # Use input or default
        if [ -z "$input_path" ] && [ -n "$default_path" ]; then
            wg_conf_path="$default_path"
        else
            wg_conf_path="$input_path"
        fi

        echo -e "   ${BLUE}👉 This file contains your private key and peer settings for the home VPN.${NC}"
        if [ -f "$wg_conf_path" ]; then
            echo "$wg_conf_path"
            # Update global var for saving later
            WG_CONF_PATH="$wg_conf_path" 
            break
        else
            warn "File not found: $wg_conf_path. Please try again."
        fi
    done
}

get_ip_range() {
    local default_cidr="${LAN_CIDR:-10.10.10.0/24}"
    
    echo -ne "🌐 Enter LAN IP range (CIDR) [default: ${YELLOW}$default_cidr${NC}]: "
    read -r input_cidr
    
    if [ -z "$input_cidr" ]; then
        LAN_CIDR="$default_cidr"
    else
        LAN_CIDR="$input_cidr"
    fi
    
    echo -e "   ${BLUE}👉 The private subnet for devices connecting to the AP (LAN side).${NC}"
    echo "$LAN_CIDR"
}

main() {
    trap cleanup_on_interrupt SIGINT
    load_config # Load defaults from file if it exists
    init_log
    check_root
    print_header

    info "Checking System Dependencies..."
    
    # Check which packages are missing
    MISSING_PKGS=""
    if ! dpkg -s wireguard >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS wireguard"; fi
    if ! dpkg -s dnsmasq >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS dnsmasq"; fi
    if ! dpkg -s iptables >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS iptables"; fi
    if ! dpkg -s qrencode >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS qrencode"; fi

    if [ -n "$MISSING_PKGS" ]; then
        echo -e "   ${YELLOW}Missing packages:${NC}$MISSING_PKGS"
        echo -ne "❓ ${YELLOW}Do you want to install necessary packages?$MISSING_PKGS [Y/n]${NC} "
        read -r install_choice
        if [[ "$install_choice" =~ ^[Nn]$ ]]; then
            error "Package installation is required to proceed. Exiting."
            exit 1
        else
            run_step "Updating package list" "apt-get update"
            run_step "Installing missing packages" "apt-get install -y $MISSING_PKGS"
        fi
    else
        success "All base dependencies (wireguard, dnsmasq, iptables, qrencode) are already installed."
    fi

    echo ""
    info "Network Interface Selection"
    echo -e "   ${BLUE}👉 Identify which port connects to the Internet (WAN) and which serves the local private network (LAN).${NC}"
    echo "------------------------------------------------"
    
    echo -e "\n${BOLD}Step 1: Select the WAN interface${NC}"
    echo -e "   ${BLUE}ℹ️  This interface connects to the upstream Internet (e.g., USB adapter or built-in Ethernet connected to the site's router).${NC}"
    WAN_IFACE=$(select_interface "Available interfaces:" "$WAN_IFACE")
    # Clean up output captured from select_interface (just in case)
    # The select_interface function echoes prompts to stdout which are captured by $() if not redirected to stderr.
    # We need to fix select_interface to print prompts to stderr or handle capture differently.
    # Current issue: 'Available interfaces:' string is being captured.
    
    # FIX: Refactor select_interface to print UI to stderr so only the result goes to stdout
    
    save_config_var "WAN_IFACE" "$WAN_IFACE"
    success "WAN Interface selected: $WAN_IFACE"
    
    echo -e "\n${BOLD}Step 2: Select the LAN interface${NC}"
    echo -e "   ${BLUE}ℹ️  This interface will host the secure private subnet (e.g., built-in Ethernet connected to your Access Point).${NC}"
    echo -e "   ${YELLOW}👉 If you select a wireless interface (e.g., wlan0), the Pi will be configured as a Wi-Fi Access Point.${NC}"
    LAN_IFACE=$(select_interface "Available interfaces:" "$LAN_IFACE")
    save_config_var "LAN_IFACE" "$LAN_IFACE"
    success "LAN Interface selected: $LAN_IFACE"
    echo ""

    if [ "$WAN_IFACE" == "$LAN_IFACE" ]; then
        error "WAN and LAN interfaces cannot be the same."
        exit 1
    fi

    # Check for Wireless LAN Interface
    IS_WIRELESS=false
    # More robust check: simple string matching
    if echo "$LAN_IFACE" | grep -q "wlan"; then
        IS_WIRELESS=true
        save_config_var "IS_WIRELESS" "true"
        info "Wireless LAN interface detected ($LAN_IFACE)."
        echo -e "   ${BLUE}ℹ️  To use this interface for the private subnet, the Pi must act as a Wi-Fi Access Point.${NC}"
        echo -e "   ${BLUE}ℹ️  This requires installing 'hostapd' (Host Access Point Daemon).${NC}"
        
        if dpkg -s hostapd >/dev/null 2>&1; then
             success "'hostapd' is already installed."
        else
            echo -ne "❓ ${YELLOW}Do you want to proceed with installing hostapd? [Y/n]${NC} "
            read -r ap_install_choice
            if [[ "$ap_install_choice" =~ ^[Nn]$ ]]; then
                error "Cannot proceed with wireless LAN without hostapd. Exiting."
                exit 1
            fi
            run_step "Installing hostapd" "apt-get install -y hostapd"
        fi

        # Pre-fill SSID from config
        default_ssid="${AP_SSID:-}"
        prompt_ssid="📡 Enter SSID (Network Name) for the AP"
        if [ -n "$default_ssid" ]; then
             prompt_ssid="$prompt_ssid [default: ${YELLOW}$default_ssid${NC}]"
        fi
        echo -ne "$prompt_ssid: "
        read -r input_ssid
        if [ -z "$input_ssid" ] && [ -n "$default_ssid" ]; then
            AP_SSID="$default_ssid"
        else
            AP_SSID="$input_ssid"
        fi
        save_config_var "AP_SSID" "$AP_SSID"
        
        # Pre-fill Password from config (warn user)
        default_pass="${AP_PASS:-}"
        prompt_pass="🔑 Enter Password for the AP (min 8 chars)"
        if [ -n "$default_pass" ]; then
             prompt_pass="$prompt_pass [default: ${YELLOW}********${NC}]"
        fi
        
        while true; do
            echo -ne "$prompt_pass: "
            read -r -s input_pass
            echo ""
            
            # Logging input length only, not the password itself
            echo "[DEBUG] Password input received. Length: ${#input_pass}" >> "$LOG_FILE"
            
            if [ -z "$input_pass" ] && [ -n "$default_pass" ]; then
                AP_PASS="$default_pass"
                break
            elif [ ${#input_pass} -ge 8 ]; then
                AP_PASS="$input_pass"
                break
            else
                warn "Password must be at least 8 characters."
                echo "[DEBUG] Password too short." >> "$LOG_FILE"
            fi
        done
        save_config_var "AP_PASS" "$AP_PASS"
    else
        save_config_var "IS_WIRELESS" "false"
    fi

    LAN_CIDR=$(get_ip_range)
    save_config_var "LAN_CIDR" "$LAN_CIDR"
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
    save_config_var "WG_CONF_PATH" "$WG_CONF_SRC"
    WG_CONF_DEST="/etc/wireguard/wg0.conf"

    echo ""
    run_step "Installing WireGuard config" "cp \"$WG_CONF_SRC\" \"$WG_CONF_DEST\" && chmod 600 \"$WG_CONF_DEST\""

    run_step "Enabling IP Forwarding" "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn-gateway.conf && sysctl -p /etc/sysctl.d/99-vpn-gateway.conf"

    # Configure static IP for LAN interface
    echo -ne "⏳ ${CYAN}Configuring Network Interfaces (Static IP)...${NC} "
    {
        echo "[Configuring Network Interfaces]" >> "$LOG_FILE"
        
        # Detect Network Manager
        if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
            echo "Detected NetworkManager. Using nmcli..." >> "$LOG_FILE"
            
            # Create or modify connection for LAN interface
            # Try to find existing connection for this interface
            CON_NAME=$(nmcli -t -f NAME,DEVICE connection show | grep ":$LAN_IFACE$" | cut -d: -f1 | head -n1)
            
            if [ -z "$CON_NAME" ]; then
                CON_NAME="Wired connection $LAN_IFACE" # Default name attempt or create new
                nmcli con add type ethernet ifname "$LAN_IFACE" con-name "$CON_NAME" >> "$LOG_FILE" 2>&1
            fi
            
            # Apply Static IP
            nmcli con modify "$CON_NAME" ipv4.addresses "$LAN_GATEWAY/24" ipv4.method manual >> "$LOG_FILE" 2>&1
            nmcli con up "$CON_NAME" >> "$LOG_FILE" 2>&1
            
        elif [ -f /etc/dhcpcd.conf ]; then
             echo "Detected dhcpcd..." >> "$LOG_FILE"
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
            echo "No supported network manager found (NetworkManager or dhcpcd). Falling back to 'ip addr'..." >> "$LOG_FILE"
            ip addr add "$LAN_GATEWAY/24" dev "$LAN_IFACE" >> "$LOG_FILE" 2>&1
        fi
    } || { echo -e "[${RED}FAIL${NC}]"; exit 1; }
    echo -e "[${GREEN}DONE${NC}]"
    echo -e "   ${BLUE}👉 Assigned static IP $LAN_GATEWAY to $LAN_IFACE (LAN)${NC}"

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

    # Configure hostapd if wireless
    if [ "$IS_WIRELESS" = true ]; then
        echo -ne "⏳ ${CYAN}Configuring Access Point (hostapd)...${NC} "
        {
            cat > /etc/hostapd/hostapd.conf <<EOF
interface=$LAN_IFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$AP_PASS
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
            # Point daemon to config
            # (On some Pi OS versions, modifying /etc/default/hostapd is needed, but modern systemd service often looks at /etc/hostapd/hostapd.conf automatically or needs override)
            # Standard Pi OS way:
            sed -i 's|#DAEMON_CONF=""|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

            # Unblock wlan
            rfkill unblock wlan >> "$LOG_FILE" 2>&1
            
            systemctl unmask hostapd >> "$LOG_FILE" 2>&1
            systemctl enable hostapd >> "$LOG_FILE" 2>&1
            systemctl restart hostapd >> "$LOG_FILE" 2>&1
        } || { echo -e "[${RED}FAIL${NC}]"; exit 1; }
        echo -e "[${GREEN}DONE${NC}]"
    fi


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
    
    save_config
    info "Configuration saved to: $CONFIG_FILE"
}

main
