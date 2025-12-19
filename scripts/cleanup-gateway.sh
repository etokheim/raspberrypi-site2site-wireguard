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

# --- Colors & Styles ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Progress Box System ---
declare -a PROGRESS_STEPS=()
declare -a PROGRESS_STATUS=()
declare -a PROGRESS_EXTRA=()
PROGRESS_BOX_LINES=0

progress_add_step() {
    local name="$1"
    local extra="${2:-}"
    PROGRESS_STEPS+=("$name")
    PROGRESS_STATUS+=("pending")
    PROGRESS_EXTRA+=("$extra")
}

progress_set_status() {
    local index="$1"
    local status="$2"
    local extra="${3:-}"
    PROGRESS_STATUS[$index]="$status"
    [ -n "$extra" ] && PROGRESS_EXTRA[$index]="$extra"
}

progress_find_step() {
    local name="$1"
    for i in "${!PROGRESS_STEPS[@]}"; do
        if [[ "${PROGRESS_STEPS[$i]}" == "$name" ]]; then
            echo "$i"
            return
        fi
    done
    echo "-1"
}

progress_draw_box() {
    # Box is 76 chars: │ + space + 72 content + space + │
    local box_w=76
    local content_w=72
    local border
    border=$(printf '─%.0s' $(seq 1 $((box_w - 2))))
    
    # Move cursor up and clear lines if we've drawn before
    if [ "$PROGRESS_BOX_LINES" -gt 0 ]; then
        for ((j=0; j<PROGRESS_BOX_LINES; j++)); do
            printf "\033[A\033[2K"
        done
    fi
    
    local lines=0
    
    # Header
    echo -e "${RED}╭${border}╮${NC}"
    echo -e "${RED}│${NC} ${BOLD}${YELLOW}🧹 Cleanup Progress${NC}$(printf '%*s' $((content_w - 19)) '') ${RED}│${NC}"
    echo -e "${RED}├${border}┤${NC}"
    lines=$((lines + 3))
    
    # Steps
    for i in "${!PROGRESS_STEPS[@]}"; do
        local step="${PROGRESS_STEPS[$i]}"
        local status="${PROGRESS_STATUS[$i]}"
        local extra="${PROGRESS_EXTRA[$i]}"
        local icon color
        
        case "$status" in
            pending) icon="○"; color="${DIM}" ;;
            running) icon="◐"; color="${YELLOW}" ;;
            done)    icon="✔"; color="${GREEN}" ;;
            fail)    icon="✖"; color="${RED}" ;;
            skip)    icon="◌"; color="${DIM}" ;;
        esac
        
        # Build the display text (for length calculation)
        local display_text="$icon $step"
        [ -n "$extra" ] && display_text="$display_text $extra"
        
        # Truncate if too long
        local text_len=${#display_text}
        if [ $text_len -gt $content_w ]; then
            if [ -n "$extra" ]; then
                # Truncate step to fit
                local max_step=$((content_w - ${#extra} - 6))  # icon + spaces + ...
                step="${step:0:$max_step}..."
                display_text="$icon $step $extra"
            else
                step="${step:0:$((content_w - 4))}..."
                display_text="$icon $step"
            fi
            text_len=${#display_text}
        fi
        
        local padding=$((content_w - text_len))
        
        # Print the line
        if [ -n "$extra" ]; then
            echo -e "${RED}│${NC} ${color}${icon} ${step}${NC} ${DIM}${extra}${NC}$(printf '%*s' $padding '') ${RED}│${NC}"
        else
            echo -e "${RED}│${NC} ${color}${display_text}${NC}$(printf '%*s' $padding '') ${RED}│${NC}"
        fi
        lines=$((lines + 1))
    done
    
    # Footer
    echo -e "${RED}╰${border}╯${NC}"
    lines=$((lines + 1))
    
    PROGRESS_BOX_LINES=$lines
}

progress_run_step() {
    local step_name="$1"
    shift
    local cmd="$@"
    
    local idx
    idx=$(progress_find_step "$step_name")
    if [ "$idx" = "-1" ]; then
        # Step not in list, just run it
        eval "$cmd" >> "$LOG_FILE" 2>&1
        return $?
    fi
    
    progress_set_status "$idx" "running"
    progress_draw_box
    
    # Run the command in background
    echo "[$step_name] Executing: $cmd" >> "$LOG_FILE"
    eval "$cmd" >> "$LOG_FILE" 2>&1 &
    local pid=$!
    
    # Animated spinner while waiting
    local spin_frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local frame=0
    
    printf "   "
    while kill -0 $pid 2>/dev/null; do
        printf "\r   ${YELLOW}${spin_frames[$frame]}${NC} Running: ${DIM}%s${NC}   " "$step_name"
        frame=$(( (frame + 1) % ${#spin_frames[@]} ))
        sleep 0.1
    done
    printf "\r\033[K"
    
    wait $pid
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        progress_set_status "$idx" "done"
    else
        progress_set_status "$idx" "fail"
    fi
    progress_draw_box
    
    return $exit_code
}

progress_skip_step() {
    local step_name="$1"
    local idx
    idx=$(progress_find_step "$step_name")
    [ "$idx" != "-1" ] && progress_set_status "$idx" "skip"
}

progress_clear() {
    PROGRESS_STEPS=()
    PROGRESS_STATUS=()
    PROGRESS_EXTRA=()
    PROGRESS_BOX_LINES=0
}

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

cleanup_dns_resolvconf() {
    # If dnsmasq registered 127.0.0.1 with resolvconf, it might persist after service stop.
    # We must explicitly remove it to restore upstream DNS.
    if command -v resolvconf >/dev/null 2>&1; then
        echo "[cleanup_dns] Removing lo.dnsmasq from resolvconf..." >> "$LOG_FILE"
        resolvconf -d lo.dnsmasq >> "$LOG_FILE" 2>&1 || true
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
    echo ""
    echo -e "📄 Log file: ${YELLOW}$LOG_FILE${NC}"
    echo ""
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

    # --- Build Progress Steps ---
    progress_clear
    
    progress_add_step "Stop WireGuard service"
    progress_add_step "Bring down WireGuard interface"
    progress_add_step "Stop DHCP server" "(dnsmasq)"
    progress_add_step "Clean up DNS" "(resolvconf)"
    
    # Check if hostapd is active
    local hostapd_active=false
    if systemctl is-active --quiet hostapd 2>/dev/null; then
        hostapd_active=true
        progress_add_step "Stop Access Point" "(hostapd)"
    fi
    
    if [ "${FIREWALL_ENABLED:-true}" = "true" ]; then
        progress_add_step "Remove WAN firewall rules"
    fi
    
    progress_add_step "Remove NAT/forward rules"
    progress_add_step "Disable IP forwarding"
    
    if [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ]; then
        progress_add_step "Remove auto-updates config"
    fi
    
    progress_add_step "Remove software watchdog"
    
    if [ "${WATCHDOG_ENABLED:-false}" = "true" ]; then
        progress_add_step "Remove hardware watchdog"
    fi
    
    if command -v netfilter-persistent >/dev/null 2>&1; then
        progress_add_step "Save firewall rules"
    fi
    
    progress_add_step "Restore network config"
    progress_add_step "Restore backup files"
    
    # Draw initial progress box
    progress_draw_box
    
    echo ""
    if [ "${NONINTERACTIVE:-false}" = "true" ]; then
        echo "Non-interactive mode: proceeding with cleanup."
    else
        echo -ne "${BOLD}Proceed with cleanup/restore? [Y/n]:${NC} "
        read -r proceed_choice
        if [[ "$proceed_choice" =~ ^[Nn]$ ]]; then
            echo "Aborting cleanup by user request."
            exit 1
        fi
    fi
    
    # Reset box lines after prompt
    PROGRESS_BOX_LINES=0
    echo ""

    # --- Execute Steps ---
    
    progress_run_step "Stop WireGuard service" "systemctl stop wg-quick@wg0 2>/dev/null; systemctl disable wg-quick@wg0 2>/dev/null; true"
    
    progress_run_step "Bring down WireGuard interface" "if ip link show wg0 >/dev/null 2>&1; then wg-quick down wg0 2>/dev/null; fi; true"

    progress_run_step "Stop DHCP server" "systemctl stop dnsmasq 2>/dev/null; systemctl disable dnsmasq 2>/dev/null; true"
    
    progress_run_step "Clean up DNS" "cleanup_dns_resolvconf"

    if [ "$hostapd_active" = true ]; then
        progress_run_step "Stop Access Point" "systemctl stop hostapd; systemctl disable hostapd"
    fi

    if [ "${FIREWALL_ENABLED:-true}" = "true" ]; then
        progress_run_step "Remove WAN firewall rules" "cleanup_wan_firewall_rules"
    fi

    progress_run_step "Remove NAT/forward rules" "cleanup_gateway_nat_rules"

    progress_run_step "Disable IP forwarding" "rm -f /etc/sysctl.d/99-vpn-gateway.conf && sysctl --system >/dev/null 2>&1"

    if [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ]; then
        progress_run_step "Remove auto-updates config" "remove_auto_updates"
    fi

    progress_run_step "Remove software watchdog" "remove_software_watchdog"

    if [ "${WATCHDOG_ENABLED:-false}" = "true" ]; then
        progress_run_step "Remove hardware watchdog" "remove_hardware_watchdog"
    fi

    if command -v netfilter-persistent >/dev/null 2>&1; then
        progress_run_step "Save firewall rules" "netfilter-persistent save"
    fi

    # Restore network configuration
    progress_run_step "Restore network config" "
        if [ -n '$LAN_IFACE' ]; then
            ip addr flush dev '$LAN_IFACE' 2>/dev/null || true
        fi
        if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
            if [ -n '$LAN_IFACE' ]; then
                CON_NAME=\$(nmcli -t -f NAME,DEVICE connection show | grep ':$LAN_IFACE$' | cut -d: -f1 | head -n1)
                if [ -n \"\$CON_NAME\" ]; then
                    nmcli con modify \"\$CON_NAME\" ipv4.method auto 2>/dev/null || true
                    nmcli con up \"\$CON_NAME\" 2>/dev/null || true
                fi
            fi
        elif [ -f /etc/dhcpcd.conf ]; then
            sed -i '/# VPN-GATEWAY-START/,/# VPN-GATEWAY-END/d' /etc/dhcpcd.conf
            systemctl restart dhcpcd 2>/dev/null || true
        fi
        true
    "

    # Restore backup configuration files
    progress_run_step "Restore backup files" "
        if [ -f /etc/dnsmasq.conf.bak ]; then
            mv /etc/dnsmasq.conf.bak /etc/dnsmasq.conf 2>/dev/null || true
        fi
        if [ '${IS_WIRELESS:-false}' = 'true' ]; then
            rm -f /etc/hostapd/hostapd.conf 2>/dev/null || true
            if [ -f /etc/default/hostapd ]; then
                sed -i 's|DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"|#DAEMON_CONF=\"\"|' /etc/default/hostapd 2>/dev/null || true
            fi
        fi
        if [ -f /etc/wireguard/wg0.conf ]; then
            rm -f /etc/wireguard/wg0.conf 2>/dev/null || true
        fi
        true
    "
    
    # Final redraw
    progress_draw_box

    echo ""
    echo -e "${GREEN}${BOLD}╭──────────────────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${GREEN}${BOLD}│                          ✔ Restore Complete!                             │${NC}"
    echo -e "${GREEN}${BOLD}╰──────────────────────────────────────────────────────────────────────────╯${NC}"
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
