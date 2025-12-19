#!/bin/bash

# setup-vpn-gateway.sh
# Configures Raspberry Pi as a VPN Gateway with WireGuard and dnsmasq.
# Enhanced with UI improvements and logging.

set -o pipefail

# --- Paths & Configuration ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOG_DIR/vpn_setup.log"
CONFIG_FILE="$ROOT_DIR/vpn-gateway.conf"
LEGACY_CONFIG_1="$ROOT_DIR/gateway.conf"
LEGACY_CONFIG_2="$ROOT_DIR/vpn_gateway.conf"
TERM_WIDTH=$(tput cols)

# --- Configuration Loading ---
load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$LEGACY_CONFIG_1" ]; then
            mv "$LEGACY_CONFIG_1" "$CONFIG_FILE"
        elif [ -f "$LEGACY_CONFIG_2" ]; then
            mv "$LEGACY_CONFIG_2" "$CONFIG_FILE"
        fi
    fi

    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
}

has_full_config() {
    [ -n "$WAN_IFACE" ] && [ -n "$LAN_IFACE" ] && [ -n "$LAN_CIDR" ] && [ -n "$WG_CONF_PATH" ]
}

show_existing_config() {
    echo "📄 Existing configuration loaded from $CONFIG_FILE:"
    echo "  • WAN interface: ${WAN_IFACE:-<unset>}"
    echo "  • LAN interface: ${LAN_IFACE:-<unset>}"
    echo "  • LAN CIDR: ${LAN_CIDR:-<unset>}"
    echo "  • WireGuard config: ${WG_CONF_PATH:-<unset>}"
    if [ "${IS_WIRELESS:-false}" = "true" ]; then
        echo "  • Wi‑Fi SSID: ${AP_SSID:-<unset>}"
    fi
    echo "  • Firewall: ${FIREWALL_ENABLED:-true}"
    echo "  • Auto updates: ${AUTO_UPDATES_ENABLED:-false}"
}

detect_ssh_port() {
    if [ -n "${SSH_PORT:-}" ]; then
        return
    fi
    local detected
    detected=$(grep -iE '^Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}')
    if echo "$detected" | grep -qE '^[0-9]+$'; then
        SSH_PORT="$detected"
    else
        SSH_PORT="22"
    fi
    save_config_var "SSH_PORT" "$SSH_PORT"
}

parse_wg_listen_port() {
    local cfg="$1"
    local port
    port=$(grep -iE '^ListenPort' "$cfg" 2>/dev/null | tail -n1 | awk -F'=' '{gsub(/ /,"",$2); print $2}')
    if echo "$port" | grep -qE '^[0-9]+$'; then
        WG_LISTEN_PORT="$port"
        save_config_var "WG_LISTEN_PORT" "$WG_LISTEN_PORT"
    fi
}

ensure_service_restart_policy() {
    local svc="$1"
    local dropin_dir="/etc/systemd/system/${svc}.d"
    mkdir -p "$dropin_dir"
    cat > "${dropin_dir}/override.conf" <<EOF
[Service]
Restart=on-failure
RestartSec=5
EOF
    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || true
}

ensure_watchdog() {
    run_step "Enabling watchdog" "bash -c \"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update >> '$LOG_FILE' 2>&1
        apt-get install -y watchdog >> '$LOG_FILE' 2>&1
        if [ -f /etc/watchdog.conf ] && [ ! -f /etc/watchdog.conf.bak_gateway ]; then
            cp /etc/watchdog.conf /etc/watchdog.conf.bak_gateway
        fi
        cat > /etc/watchdog.conf <<EOF
watchdog-device = /dev/watchdog
max-load-1 = 24
interface = $LAN_IFACE
realtime = yes
priority = 1
EOF
        systemctl enable --now watchdog >> '$LOG_FILE' 2>&1 || true
    \""
}

disable_unused_services() {
    local services=("avahi-daemon.service" "avahi-daemon.socket" "cups.service" "cups-browsed.service" "bluetooth.service")
    for svc in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}"; then
            systemctl disable --now "$svc" >> "$LOG_FILE" 2>&1 || true
        fi
    done
}

ensure_wg_perms() {
    local path="$1"
    if [ ! -f "$path" ]; then
        warn "WireGuard config not found at $path (skipping perm check)."
        return
    fi
    local mode owner group
    mode=$(stat -c "%a" "$path")
    owner=$(stat -c "%U" "$path")
    group=$(stat -c "%G" "$path")
    if [ "$mode" -le 600 ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        return
    fi
    if [ "$NONINTERACTIVE" = "true" ]; then
        info "Non-interactive: fixing WireGuard config permissions at $path"
        chown root:root "$path"
        chmod 600 "$path"
        return
    fi
    echo -ne "❓ ${YELLOW}WireGuard config $path has loose permissions ($mode $owner:$group). Fix to 600 root:root? [Y/n]${NC} "
    read -r fix_perm
    if [[ ! "$fix_perm" =~ ^[Nn]$ ]]; then
        chown root:root "$path"
        chmod 600 "$path"
        success "Permissions corrected for $path"
    else
        warn "Left WireGuard config permissions unchanged."
    fi
}

is_wg_active() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wg-quick@wg0; then
        return 0
    fi
    ip link show wg0 >/dev/null 2>&1
}

reset_previous_lan_iface() {
    local old_iface="$1"
    local new_iface="$2"
    local old_wireless="$3"

    if [ -z "$old_iface" ] || [ "$old_iface" = "$new_iface" ]; then
        return
    fi

    echo "[Reconfig] Clearing previous LAN interface $old_iface" >> "$LOG_FILE"

    # Detach NetworkManager configuration on the previous LAN interface
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
        local old_con
        old_con=$(nmcli -t -f NAME,DEVICE connection show | grep ":$old_iface$" | cut -d: -f1 | head -n1)
        if [ -n "$old_con" ]; then
            nmcli con modify "$old_con" ipv4.method auto >> "$LOG_FILE" 2>&1 || true
            nmcli con down "$old_con" >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    # Flush any static addresses on the old LAN interface
    ip addr flush dev "$old_iface" >> "$LOG_FILE" 2>&1 || true

    # If we previously configured hostapd on that interface but are no longer wireless, stop it
    if [ "$old_wireless" = "true" ] && ! echo "$new_iface" | grep -q "wlan"; then
        systemctl stop hostapd >> "$LOG_FILE" 2>&1 || true
        systemctl disable hostapd >> "$LOG_FILE" 2>&1 || true
    fi
}

save_config_var() {
    local var_name="$1"
    local var_value="$2"
    
    echo "[DEBUG] Saving $var_name..." >> "$LOG_FILE"
    
    # Create file if not exists
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "# VPN Gateway Configuration" > "$CONFIG_FILE"
        echo "# Generated on $(date)" >> "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    fi
    
    # Check if var exists in file
    if grep -q "^$var_name=" "$CONFIG_FILE"; then
        # Use grep -v to remove the line and then append the new one
        # This avoids complex sed escaping issues
        grep -v "^$var_name=" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"
        echo "$var_name=\"$var_value\"" >> "${CONFIG_FILE}.tmp"
        mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    else
        # Append new var
        echo "$var_name=\"$var_value\"" >> "$CONFIG_FILE"
    fi
    echo "[DEBUG] Saved $var_name." >> "$LOG_FILE"
}

save_full_config() {
    # Legacy function kept for final save, but now redundant with incremental saves
    # We'll just update the timestamp header if we want, or do nothing.
    :
}

# Wrapper retained for compatibility
save_config() {
    save_full_config
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
    if [ "${APPLYING_CHANGES:-false}" = "false" ]; then
        echo ""
        echo "Aborted before applying changes. No modifications were made."
        exit 1
    fi

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
        local cleanup_script="$ROOT_DIR/scripts/cleanup-gateway.sh"
        if [ -f "$cleanup_script" ]; then
            bash "$cleanup_script"
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
    mkdir -p "$LOG_DIR"
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
    echo -e "${GREEN}✔ $1${NC}"
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

# Ensure iptables forwarding/NAT rules exist for LAN -> wg0
ensure_nat_rules() {
    echo "[ensure_nat_rules] Verifying iptables rules for $LAN_IFACE -> wg0" >> "$LOG_FILE"
    # Forward LAN to wg0
    if ! iptables -C FORWARD -i "$LAN_IFACE" -o wg0 -j ACCEPT >/dev/null 2>&1; then
        iptables -A FORWARD -i "$LAN_IFACE" -o wg0 -j ACCEPT >> "$LOG_FILE" 2>&1
    fi
    # Allow return traffic from wg0 to LAN
    if ! iptables -C FORWARD -i wg0 -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
        iptables -A FORWARD -i wg0 -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT >> "$LOG_FILE" 2>&1
    fi
    # NAT out wg0
    if ! iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE >/dev/null 2>&1; then
        iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE >> "$LOG_FILE" 2>&1
    fi
    # NAT out WAN as secondary path (if desired)
    if [ -n "$WAN_IFACE" ] && ! iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE >/dev/null 2>&1; then
        iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE >> "$LOG_FILE" 2>&1
    fi
}

ensure_wan_firewall_rules() {
    echo "[wan_firewall] Applying hardened INPUT rules for WAN=$WAN_IFACE" >> "$LOG_FILE"
    local ssh_port="${SSH_PORT:-22}"

    # Allow LAN management traffic
    if ! iptables -C INPUT -i "$LAN_IFACE" -j ACCEPT >/dev/null 2>&1; then
        iptables -A INPUT -i "$LAN_IFACE" -j ACCEPT >> "$LOG_FILE" 2>&1
    fi

    # Allow established/related on WAN
    if ! iptables -C INPUT -i "$WAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
        iptables -A INPUT -i "$WAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT >> "$LOG_FILE" 2>&1
    fi

    # Allow SSH on WAN
    if ! iptables -C INPUT -i "$WAN_IFACE" -p tcp --dport "$ssh_port" -j ACCEPT >/dev/null 2>&1; then
        iptables -A INPUT -i "$WAN_IFACE" -p tcp --dport "$ssh_port" -j ACCEPT >> "$LOG_FILE" 2>&1
    fi

    # Allow WireGuard listen port if present
    if [ -n "${WG_LISTEN_PORT:-}" ]; then
        if ! iptables -C INPUT -i "$WAN_IFACE" -p udp --dport "$WG_LISTEN_PORT" -j ACCEPT >/dev/null 2>&1; then
            iptables -A INPUT -i "$WAN_IFACE" -p udp --dport "$WG_LISTEN_PORT" -j ACCEPT >> "$LOG_FILE" 2>&1
        fi
    fi

    # Drop everything else on WAN INPUT
    if ! iptables -C INPUT -i "$WAN_IFACE" -j DROP >/dev/null 2>&1; then
        iptables -A INPUT -i "$WAN_IFACE" -j DROP >> "$LOG_FILE" 2>&1
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

    # Print menu to stderr to keep stdout clean
    echo "" >&2
    echo -e "${BOLD}$prompt_text${NC}" >&2

    # Build arrays for selection
    local idx=1
    local iface_list=()
    for iface in $interfaces; do
        printf "   %2d) %s\n" "$idx" "$iface" >&2
        iface_list+=("$iface")
        idx=$((idx + 1))
    done
    echo "" >&2

    # Build colored prompt
    local prompt="👉 \e[1;34mSelect interface number"
    if [ -n "$default_iface" ]; then
        prompt+=" [Default: \e[1;33m${default_iface}\e[0m]"
    fi
    prompt+=": \e[0m"

    while true; do
        # read from tty to avoid capture issues
        read -r -p "$(echo -e "$prompt")" choice < /dev/tty

        if [ -z "$choice" ] && [ -n "$default_iface" ]; then
            chosen_iface="$default_iface"
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#iface_list[@]}" ]; then
            chosen_iface="${iface_list[$((choice-1))]}"
            break
        else
            if [ -n "$default_iface" ]; then
                warn "Invalid selection. Press Enter for default or choose a valid number." >&2
            else
                warn "Invalid selection. Please try again." >&2
            fi
        fi
    done

    echo "$chosen_iface"
}

get_wg_config() {
    # Pre-fill default from config if available
    local default_path="${WG_CONF_PATH:-}"
    
    while true; do
        # Prompt to stderr so it is visible when stdout is captured by command substitution.
        # Use readline (-e) with optional initial text for tab completion and easier editing.
        if [ -n "$default_path" ]; then
            printf "📂 Enter path to WireGuard peer config file [default: \e[1;33m%s\e[0m]: " "$default_path" >&2
            read -e -i "$default_path" -r input_path < /dev/tty
        else
            printf "📂 Enter path to WireGuard peer config file: " >&2
            read -e -r input_path < /dev/tty
        fi
        
        # Use input or default
        if [ -z "$input_path" ] && [ -n "$default_path" ]; then
            wg_conf_path="$default_path"
        else
            wg_conf_path="$input_path"
        fi

        echo -e "   ${BLUE}👉 This file contains your private key and peer settings for the home VPN.${NC}" >&2
        if [ -f "$wg_conf_path" ]; then
            echo "$wg_conf_path"
            # Update global var for saving later
            WG_CONF_PATH="$wg_conf_path" 
            break
        else
            warn "File not found: $wg_conf_path. Please try again." >&2
        fi
    done
}

get_ip_range() {
    local default_cidr="${LAN_CIDR:-10.10.10.0/24}"
    
    # Debug logging
    echo "[DEBUG] Entering get_ip_range function" >> "$LOG_FILE"
    
    # Prompt on stderr so it is visible even when this function is used in a
    # command substitution (stdout is captured for the return value).
    echo -ne "🌐 Enter LAN IP range (CIDR, forced to /24) [default: ${BOLD}${YELLOW}$default_cidr${NC}]: " >&2
    
    # Force read from terminal
    read -r input_cidr < /dev/tty
    
    echo "[DEBUG] Read IP input: '$input_cidr'" >> "$LOG_FILE"
    
    if [ -z "$input_cidr" ]; then
        LAN_CIDR="$default_cidr"
    else
        # Strip any existing prefix and force /24
        local ip_only prefix
        ip_only=$(echo "$input_cidr" | cut -d'/' -f1)
        prefix=$(echo "$ip_only" | awk -F'.' '{print $1"."$2"."$3}')
        if echo "$prefix" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
            LAN_CIDR="${prefix}.0/24"
            echo "[DEBUG] Forcing CIDR to /24: $LAN_CIDR" >> "$LOG_FILE"
            echo -e "   ${YELLOW}ℹ️  Subnets are locked to /24; using ${LAN_CIDR}.${NC}" >&2
        else
            LAN_CIDR="$default_cidr"
            echo "[DEBUG] Invalid subnet input, falling back to default: $LAN_CIDR" >> "$LOG_FILE"
            echo -e "   ${YELLOW}⚠️  Input not recognized; using default ${LAN_CIDR}.${NC}" >&2
        fi
    fi
    
    echo -e "   ${BLUE}👉 The private subnet for devices connecting to the AP (LAN side).${NC}" >&2
    echo "$LAN_CIDR"
}

main() {
    trap cleanup_on_interrupt SIGINT
    load_config # Load defaults from file if it exists
    NONINTERACTIVE="${NONINTERACTIVE:-false}"
    USE_EXISTING_CONFIG=false
    if has_full_config; then
        show_existing_config
        if [ "$NONINTERACTIVE" = "true" ]; then
            USE_EXISTING_CONFIG=true
            info "Non-interactive mode: proceeding with existing configuration."
        else
            echo -ne "Proceed with existing configuration? [Y/n]: "
            read -r use_existing
            if [[ ! "$use_existing" =~ ^[Nn]$ ]]; then
                USE_EXISTING_CONFIG=true
            fi
        fi
    fi
    PREV_LAN_IFACE="$LAN_IFACE"
    PREV_WAN_IFACE="$WAN_IFACE"
    PREV_LAN_CIDR="$LAN_CIDR"
    PREV_IS_WIRELESS="${IS_WIRELESS:-false}"
    init_log
    check_root
    print_header

    if [ "$USE_EXISTING_CONFIG" = true ]; then
        info "Using existing configuration from $CONFIG_FILE"
    else
        info "Network Interface Selection"
        echo -e "   ${BLUE}👉 Identify which port connects to the Internet (WAN) and which serves the local private network (LAN).${NC}"
        echo "------------------------------------------------"
        
        echo -e "\n${BOLD}Step 1: Select the WAN interface${NC}"
        echo -e "   ${BLUE}ℹ️  This interface connects to the upstream Internet (e.g., USB adapter or built-in Ethernet connected to the site's router).${NC}"
        WAN_IFACE=$(select_interface "Available interfaces:" "$WAN_IFACE")
        save_config_var "WAN_IFACE" "$WAN_IFACE"
        success "WAN Interface selected: $WAN_IFACE"
        
        echo -e "\n${BOLD}Step 2: Select the LAN interface${NC}"
        echo -e "   ${BLUE}ℹ️  This interface will host the secure private subnet (e.g., built-in Ethernet connected to your Access Point).${NC}"
        echo -e "   ${YELLOW}👉 If you select a wireless interface (e.g., wlan0), the Pi will be configured as a Wi-Fi Access Point.${NC}"
        LAN_IFACE=$(select_interface "Available interfaces:" "$LAN_IFACE")
        save_config_var "LAN_IFACE" "$LAN_IFACE"
        if [ -n "$PREV_LAN_IFACE" ] && [ "$PREV_LAN_IFACE" != "$LAN_IFACE" ]; then
            info "Detected LAN change: $PREV_LAN_IFACE -> $LAN_IFACE (cleaning old interface state)"
            reset_previous_lan_iface "$PREV_LAN_IFACE" "$LAN_IFACE" "$PREV_IS_WIRELESS"
        fi
        success "LAN Interface selected: $LAN_IFACE"
        echo ""
    fi

    if [ "$WAN_IFACE" == "$LAN_IFACE" ]; then
        error "WAN and LAN interfaces cannot be the same."
        exit 1
    fi

    if [ "$USE_EXISTING_CONFIG" = true ]; then
        # Derive IS_WIRELESS if missing when using existing config
        if [ -z "${IS_WIRELESS:-}" ] && echo "$LAN_IFACE" | grep -q "wlan"; then
            IS_WIRELESS=true
        fi
        save_config_var "IS_WIRELESS" "${IS_WIRELESS:-false}"
    else
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
                 prompt_ssid="$prompt_ssid [default: ${BOLD}${YELLOW}$default_ssid${NC}]"
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
                 prompt_pass="$prompt_pass [default: ${BOLD}${YELLOW}********${NC}]"
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
            # Explicit log to confirm loop exit
            echo "[DEBUG] Password accepted." >> "$LOG_FILE"
            save_config_var "AP_PASS" "$AP_PASS"
        else
            save_config_var "IS_WIRELESS" "false"
        fi
    fi

    echo "" # Add newline for clarity
    echo "[DEBUG] Starting IP Range prompt..." >> "$LOG_FILE"
    
    if [ "$USE_EXISTING_CONFIG" = true ] && [ -n "$LAN_CIDR" ]; then
        info "Using existing LAN CIDR: $LAN_CIDR"
    else
        LAN_CIDR=$(get_ip_range)
        # The output of get_ip_range is captured into LAN_CIDR. 
        # If get_ip_range has user prompts (read), they might be hidden/swallowed if not redirected to stderr!
        # Just like with select_interface, we need to fix get_ip_range to print prompts to stderr.
        
        save_config_var "LAN_CIDR" "$LAN_CIDR"
    fi
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

    if [ "$USE_EXISTING_CONFIG" = true ] && [ -n "$WG_CONF_PATH" ] && [ -f "$WG_CONF_PATH" ]; then
        WG_CONF_SRC="$WG_CONF_PATH"
        info "Using existing WireGuard config: $WG_CONF_SRC"
    else
        WG_CONF_SRC=$(get_wg_config)
        save_config_var "WG_CONF_PATH" "$WG_CONF_SRC"
    fi
    parse_wg_listen_port "$WG_CONF_SRC"
    detect_ssh_port
    WG_CONF_DEST="/etc/wireguard/wg0.conf"
    ensure_wg_perms "$WG_CONF_SRC"

    if [ "$USE_EXISTING_CONFIG" = true ]; then
        info "Using existing firewall and auto-update preferences from config."
        FIREWALL_ENABLED="${FIREWALL_ENABLED:-true}"
        AUTO_UPDATES_ENABLED="${AUTO_UPDATES_ENABLED:-false}"
        WATCHDOG_ENABLED="${WATCHDOG_ENABLED:-false}"
    else
        # Ask whether to configure firewall (WAN hardening)
        local default_fw="${FIREWALL_ENABLED:-true}"
        echo ""
        echo -ne "🛡️  Configure WAN firewall (allow SSH + WireGuard, drop other inbound)? [Y/n]: "
        read -r fw_choice
        if [[ "$fw_choice" =~ ^[Nn]$ ]]; then
            FIREWALL_ENABLED="false"
        else
            FIREWALL_ENABLED="true"
        fi
        save_config_var "FIREWALL_ENABLED" "$FIREWALL_ENABLED"

        # Ask about automatic updates (logs only, no email)
        echo ""
        echo -ne "🔄 Enable automatic updates (all packages) nightly at 03:00? [Y/n]: "
        read -r auto_updates_choice
        if [[ "$auto_updates_choice" =~ ^[Nn]$ ]]; then
            AUTO_UPDATES_ENABLED="false"
        else
            AUTO_UPDATES_ENABLED="true"
        fi
        save_config_var "AUTO_UPDATES_ENABLED" "$AUTO_UPDATES_ENABLED"

        echo ""
        echo -ne "🛠️  Enable watchdog (auto-reboot on hang)? [Y/n]: "
        read -r watchdog_choice
        if [[ "$watchdog_choice" =~ ^[Nn]$ ]]; then
            WATCHDOG_ENABLED="false"
        else
            WATCHDOG_ENABLED="true"
        fi
        save_config_var "WATCHDOG_ENABLED" "$WATCHDOG_ENABLED"
    fi

    echo ""
    # Framed summary (fixed width)
    # Keep border the same as before, but give content one extra column
    local box_w=95
    local border_inner=95 # fixed to retain outer width while widening content
    local border_line
    border_line=$(printf '═%.0s' $(seq 1 $border_inner))

    printf "╔%s╗\n" "$border_line"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "📝 Planned changes"
    printf "╠%s╣\n" "$border_line"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Configure WAN: $WAN_IFACE"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Configure LAN: $LAN_IFACE (static $LAN_GATEWAY / $LAN_CIDR)"
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• WireGuard config: $WG_CONF_SRC -> $WG_CONF_DEST"
    if [ -n "${WG_LISTEN_PORT:-}" ]; then
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• WireGuard listen UDP port: $WG_LISTEN_PORT (allowed on WAN)"
    else
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• WireGuard listen UDP port: (not detected in config)"
    fi
    printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• SSH port allowed on WAN: ${SSH_PORT:-22}"
    if [ "$FIREWALL_ENABLED" = "true" ]; then
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• WAN firewall: ENABLED (allow SSH + WireGuard; drop other inbound; allow LAN management)"
    else
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• WAN firewall: DISABLED (WAN INPUT left unchanged beyond base rules)"
    fi
    if [ "$AUTO_UPDATES_ENABLED" = "true" ]; then
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Auto updates: ENABLED (all packages nightly at 03:00)"
    else
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Auto updates: DISABLED"
    fi
    if [ "$WATCHDOG_ENABLED" = "true" ]; then
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Watchdog: ENABLED (auto-reboot on hang)"
    else
        printf "║ %-*.*s ║\n" "$box_w" "$box_w" "• Watchdog: DISABLED"
    fi
    printf "╚%s╝\n" "$border_line"
    echo ""
    if [ "$NONINTERACTIVE" = "true" ] && [ "$USE_EXISTING_CONFIG" = true ]; then
        info "Non-interactive mode: applying changes without confirmation."
        APPLYING_CHANGES=true
    else
        echo -ne "Proceed with applying these changes? [Y/n]: "
        read -r proceed_choice
        if [[ "$proceed_choice" =~ ^[Nn]$ ]]; then
            warn "Aborting setup by user request."
            exit 1
        fi
        APPLYING_CHANGES=true
    fi

    # Only generate watchdog config after the user has reviewed planned changes
    if [ "$WATCHDOG_ENABLED" = "true" ]; then
        ensure_watchdog
    fi

    info "Checking System Dependencies..."
    
    # Check which packages are missing
    MISSING_PKGS=""
    if ! dpkg -s wireguard >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS wireguard"; fi
    if ! dpkg -s dnsmasq >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS dnsmasq"; fi
    if ! dpkg -s iptables >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS iptables"; fi
    if ! dpkg -s qrencode >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS qrencode"; fi
    if ! dpkg -s resolvconf >/dev/null 2>&1; then MISSING_PKGS="$MISSING_PKGS resolvconf"; fi

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
        success "All base dependencies (wireguard, dnsmasq, iptables, qrencode, resolvconf) are already installed."
    fi

    echo ""
    run_step "Installing WireGuard config" "cp \"$WG_CONF_SRC\" \"$WG_CONF_DEST\" && chmod 600 \"$WG_CONF_DEST\""

    run_step "Enabling IP Forwarding" "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn-gateway.conf && sysctl -p /etc/sysctl.d/99-vpn-gateway.conf"

    # Configure static IP for LAN interface
    echo -ne "⏳ ${CYAN}Configuring Network Interfaces (Static IP)...${NC} "
    {
        echo "[Configuring Network Interfaces]" >> "$LOG_FILE"
        if [ -n "$PREV_LAN_CIDR" ] && [ "$PREV_LAN_CIDR" != "$LAN_CIDR" ]; then
            echo "[Reconfig] LAN CIDR change: $PREV_LAN_CIDR -> $LAN_CIDR" >> "$LOG_FILE"
        fi
        ip addr flush dev "$LAN_IFACE" >> "$LOG_FILE" 2>&1 || true
        
        # Detect Network Manager
        if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
            echo "Detected NetworkManager." >> "$LOG_FILE"

            if [ "$IS_WIRELESS" = true ]; then
                # Avoid NM connection type mismatches on wlan when hostapd will manage it.
                echo "Wireless LAN: assigning static IP directly (bypassing nmcli connection profiles)." >> "$LOG_FILE"
                ip addr add "$LAN_GATEWAY/24" dev "$LAN_IFACE" >> "$LOG_FILE" 2>&1
                ip link set "$LAN_IFACE" up >> "$LOG_FILE" 2>&1
            else
                echo "Using nmcli for wired LAN." >> "$LOG_FILE"
                # Create or modify connection for LAN interface
                CON_NAME=$(nmcli -t -f NAME,DEVICE connection show | grep ":$LAN_IFACE$" | cut -d: -f1 | head -n1)
                
                if [ -z "$CON_NAME" ]; then
                    CON_NAME="Wired connection $LAN_IFACE"
                    nmcli con add type ethernet ifname "$LAN_IFACE" con-name "$CON_NAME" >> "$LOG_FILE" 2>&1
                fi
                
                # Apply Static IP
                nmcli con modify "$CON_NAME" ipv4.addresses "$LAN_GATEWAY/24" ipv4.method manual >> "$LOG_FILE" 2>&1
                nmcli con up "$CON_NAME" >> "$LOG_FILE" 2>&1
            fi
            
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
    ensure_service_restart_policy "dnsmasq"

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
        ensure_service_restart_policy "hostapd"
    fi


    run_step "Configuring Firewall / NAT Rules" "bash -c \"
        if ! grep -q '\[Interface\]' '$WG_CONF_DEST'; then exit 1; fi;
        POST_UP='PostUp = iptables -A FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE; iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE';
        POST_DOWN='PostDown = iptables -D FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE; iptables -t nat -D POSTROUTING -o $WAN_IFACE -j MASQUERADE';
        awk -v up=\\\"\$POST_UP\\\" -v down=\\\"\$POST_DOWN\\\" '/\[Interface\]/ { print; print up; print down; next } 1' '$WG_CONF_DEST' > '${WG_CONF_DEST}.tmp' && mv '${WG_CONF_DEST}.tmp' '$WG_CONF_DEST'
    \""

    run_step "Ensuring WireGuard VPN is running" "bash -c \"
        if ip link show wg0 >/dev/null 2>&1; then
            wg-quick down wg0 || true;
        fi
        wg-quick up wg0 && systemctl enable wg-quick@wg0
    \""
    ensure_service_restart_policy "wg-quick@wg0"

    # Enforce required NAT/forward rules in case wg-quick skipped PostUp (e.g., interface already up)
    ensure_nat_rules
    if [ "$FIREWALL_ENABLED" = "true" ]; then
        ensure_wan_firewall_rules
    else
        echo "[wan_firewall] Skipped (user disabled)" >> "$LOG_FILE"
    fi

    if [ "$AUTO_UPDATES_ENABLED" = "true" ]; then
        run_step "Configuring automatic updates" "bash -c \"
            export DEBIAN_FRONTEND=noninteractive
            apt-get update >> '$LOG_FILE' 2>&1
            apt-get install -y unattended-upgrades >> '$LOG_FILE' 2>&1
            cat > /etc/apt/apt.conf.d/51unattended-upgrades-gateway <<EOF
Unattended-Upgrade::Origins-Pattern {
    \\"origin=*\\";
};
Unattended-Upgrade::Automatic-Reboot \\"true\\";
Unattended-Upgrade::Automatic-Reboot-Time \\"03:30\\";
Unattended-Upgrade::AutoFixInterruptedDpkg \\"true\\";
Unattended-Upgrade::MinimalSteps \\"true\\";
Unattended-Upgrade::Verbose \\"true\\";
Unattended-Upgrade::SyslogEnable \\"true\\";
Unattended-Upgrade::SyslogFacility \\"daemon\\";
Unattended-Upgrade::Mail \\"\\";
Unattended-Upgrade::MailOnlyOnError \\"true\\";
Unattended-Upgrade::Download-Upgradeable-Packages \\"true\\";
Unattended-Upgrade::Remove-Unused-Kernel-Packages \\"true\\";
Unattended-Upgrade::Remove-New-Unused-Dependencies \\"true\\";
Unattended-Upgrade::Remove-Unused-Dependencies \\"true\\";
Unattended-Upgrade::Keep-Debs \\"false\\";
};
EOF
            cat > /etc/apt/apt.conf.d/52periodic-gateway <<EOF
APT::Periodic::Enable \\"1\\";
APT::Periodic::Update-Package-Lists \\"1\\";
APT::Periodic::Download-Upgradeable-Packages \\"1\\";
APT::Periodic::AutocleanInterval \\"7\\";
APT::Periodic::Unattended-Upgrade \\"1\\";
APT::Periodic::Verbose \\"1\\";
EOF
            systemctl enable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer >> '$LOG_FILE' 2>&1 || true
        \""

    fi

    if [ "$WATCHDOG_ENABLED" = "true" ]; then
        ensure_watchdog
    fi

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
