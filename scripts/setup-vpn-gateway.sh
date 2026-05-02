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
TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)

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
    # Box is 76 chars wide: │ + space + 72 content + space + │
    local box_w=76
    local content_w=$((box_w - 4))  # 72 chars for content
    local label_w=18  # "  WAN interface:   " prefix length
    local field_w=$((content_w - label_w))  # 54 chars for field value
    local border
    border=$(printf '─%.0s' $(seq 1 $((box_w - 2))))
    
    # Truncate config path if too long
    local config_display="$CONFIG_FILE"
    local path_w=$((content_w - 3))  # "   " prefix
    if [ ${#config_display} -gt $path_w ]; then
        config_display="...${config_display: -$((path_w - 3))}"
    fi
    
    # Truncate WG path if too long
    local wg_display="${WG_CONF_PATH:-<unset>}"
    if [ ${#wg_display} -gt $field_w ]; then
        wg_display="...${wg_display: -$((field_w - 3))}"
    fi
    
    echo ""
    echo -e "${CYAN}╭${border}╮${NC}"
    echo -e "${CYAN}│${NC} ${BOLD}📄 Loaded Configuration${NC}$(printf '%*s' $((content_w - 23)) '') ${CYAN}│${NC}"
    printf "${CYAN}│${NC}   ${DIM}%-$((content_w - 2))s${NC} ${CYAN}│${NC}\n" "$config_display"
    echo -e "${CYAN}├${border}┤${NC}"
    printf "${CYAN}│${NC}  WAN interface:   ${BOLD}%-${field_w}s${NC} ${CYAN}│${NC}\n" "${WAN_IFACE:-<unset>}"
    if [ "${WAN_STATIC_IP_ENABLED:-false}" = "true" ]; then
        local wan_static_display="${WAN_STATIC_IP:-<unset>}/${WAN_STATIC_PREFIX:-24}"
        [ -n "${WAN_STATIC_GATEWAY:-}" ] && wan_static_display="$wan_static_display via ${WAN_STATIC_GATEWAY}"
        printf "${CYAN}│${NC}  WAN static IP:   ${BOLD}%-${field_w}s${NC} ${CYAN}│${NC}\n" "$wan_static_display"
    fi
    printf "${CYAN}│${NC}  LAN interface:   ${BOLD}%-${field_w}s${NC} ${CYAN}│${NC}\n" "${LAN_IFACE:-<unset>}"
    printf "${CYAN}│${NC}  LAN CIDR:        ${BOLD}%-${field_w}s${NC} ${CYAN}│${NC}\n" "${LAN_CIDR:-<unset>}"
    printf "${CYAN}│${NC}  WireGuard:       ${DIM}%-${field_w}s${NC} ${CYAN}│${NC}\n" "$wg_display"
    if [ "${IS_WIRELESS:-false}" = "true" ]; then
        printf "${CYAN}│${NC}  Wi-Fi SSID:      ${BOLD}%-${field_w}s${NC} ${CYAN}│${NC}\n" "${AP_SSID:-<unset>}"
    fi
    echo -e "${CYAN}├${border}┤${NC}"
    if [ "${FIREWALL_ENABLED:-true}" = "true" ]; then
        printf "${CYAN}│${NC}  ${GREEN}✔${NC} %-$((content_w - 3))s ${CYAN}│${NC}\n" "Firewall enabled"
    else
        printf "${CYAN}│${NC}  ${DIM}○${NC} %-$((content_w - 3))s ${CYAN}│${NC}\n" "Firewall disabled"
    fi
    if [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ]; then
        printf "${CYAN}│${NC}  ${GREEN}✔${NC} %-$((content_w - 3))s ${CYAN}│${NC}\n" "Auto-updates enabled"
    else
        printf "${CYAN}│${NC}  ${DIM}○${NC} %-$((content_w - 3))s ${CYAN}│${NC}\n" "Auto-updates disabled"
    fi
    if [ "${WATCHDOG_ENABLED:-false}" = "true" ]; then
        printf "${CYAN}│${NC}  ${GREEN}✔${NC} %-$((content_w - 3))s ${CYAN}│${NC}\n" "Hardware watchdog enabled"
    else
        printf "${CYAN}│${NC}  ${DIM}○${NC} %-$((content_w - 3))s ${CYAN}│${NC}\n" "Hardware watchdog disabled"
    fi
    echo -e "${CYAN}╰${border}╯${NC}"
    echo ""
}

detect_ssh_port() {
    if [ -n "${SSH_PORT:-}" ]; then
        return
    fi
    local detected=""
    # Authoritative: sshd -T resolves /etc/ssh/sshd_config + sshd_config.d/*
    if command -v sshd >/dev/null 2>&1; then
        detected=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')
    fi
    if [ -z "$detected" ]; then
        detected=$(grep -ihE '^Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
                   | tail -n1 | awk '{print $2}')
    fi
    if echo "$detected" | grep -qE '^[0-9]+$'; then
        SSH_PORT="$detected"
    else
        SSH_PORT="22"
    fi
    save_config_var "SSH_PORT" "$SSH_PORT"
}

# Detect which interface the current SSH session is bound to.
# Echoes the iface name (e.g. eth0) or empty string if not in SSH or undetectable.
detect_ssh_iface() {
    local ssh_local=""
    if [ -n "${SSH_CONNECTION:-}" ]; then
        # SSH_CONNECTION = "client_ip client_port server_ip server_port"
        ssh_local=$(echo "$SSH_CONNECTION" | awk '{print $3}')
    fi
    if [ -z "$ssh_local" ]; then
        return 0
    fi
    ip -o -4 addr show 2>/dev/null | awk -v ip="$ssh_local" '
        {
            split($4, parts, "/")
            if (parts[1] == ip) { print $2; exit }
        }'
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

do_hardware_watchdog_setup() {
    # Hardware watchdog: Uses the Pi's BCM2835 watchdog timer (/dev/watchdog)
    # If the system hangs and stops petting the watchdog, the hardware reboots the Pi
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >> "$LOG_FILE" 2>&1
    apt-get install -y -o Dpkg::Options::="--force-confold" watchdog >> "$LOG_FILE" 2>&1
    if [ -f /etc/watchdog.conf ] && [ ! -f /etc/watchdog.conf.bak_gateway ]; then
        cp /etc/watchdog.conf /etc/watchdog.conf.bak_gateway
    fi
    cat > /etc/watchdog.conf <<EOF
# Hardware watchdog - reboots only on true system hang
watchdog-device = /dev/watchdog
watchdog-timeout = 15

# Only reboot if system is completely unresponsive (load > 24 is extreme)
max-load-1 = 24

# Run with realtime priority to ensure watchdog keeps running
realtime = yes
priority = 1
EOF
    systemctl enable --now watchdog >> "$LOG_FILE" 2>&1 || true
}

ensure_hardware_watchdog() {
    run_step "Enabling hardware watchdog (auto-reboot on hang)" "do_hardware_watchdog_setup"
}

do_software_watchdog_setup() {
    # Software watchdog: systemd restart policies for critical services.
    # If a service crashes, systemd automatically restarts it after 5 seconds.
    # Also enforce startup ordering so services wait for LAN readiness.
    local lan_device_unit
    lan_device_unit=$(get_lan_device_unit)

    # Use BindsTo only for USB-backed NICs (which can transiently disappear).
    # For onboard/PCI/virtual NICs, prefer the looser Wants+After ordering.
    local lan_bus_type=""
    if [ -n "${LAN_IFACE:-}" ]; then
        lan_bus_type=$(get_interface_details "$LAN_IFACE" 2>/dev/null \
                       | sed -n '2p' | sed -n 's/.*bus=\([^ ]*\).*/\1/p')
    fi
    local binds_line=""
    if [ "$lan_bus_type" = "usb" ]; then
        binds_line="BindsTo=${lan_device_unit}"
    fi

    write_dropin() {
        local svc="$1"
        local extra_unit="$2"
        local dropin_dir="/etc/systemd/system/${svc}.d"
        mkdir -p "$dropin_dir"
        {
            printf '[Unit]\n'
            printf 'Wants=vpn-gateway-lan.service %s\n' "$lan_device_unit"
            printf 'After=vpn-gateway-lan.service %s\n' "$lan_device_unit"
            [ -n "$binds_line" ] && printf '%s\n' "$binds_line"
            [ -n "$extra_unit" ] && printf '%s\n' "$extra_unit"
            printf '\n[Service]\n'
            printf 'Restart=on-failure\n'
            printf 'RestartSec=5\n'
        } > "${dropin_dir}/override.conf"
    }

    write_dropin "dnsmasq" "$(printf 'StartLimitIntervalSec=60\nStartLimitBurst=12')"
    write_dropin "wg-quick@wg0" "Wants=network-online.target
After=network-online.target"

    if [ "${IS_WIRELESS:-false}" = "true" ]; then
        write_dropin "hostapd" ""
    fi

    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || true
}

ensure_software_watchdog() {
    run_step "Configuring software watchdog (service restart policies)" "do_software_watchdog_setup"
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
    
    # Check if permissions are secure: exactly 600 (or stricter like 400), owned by root:root
    local needs_fix=false
    if [ "$owner" != "root" ] || [ "$group" != "root" ]; then
        needs_fix=true
    elif [ "$mode" != "600" ] && [ "$mode" != "400" ]; then
        # Allow 600 or 400, reject anything else (e.g., 644, 755)
        needs_fix=true
    fi
    
    if [ "$needs_fix" = "false" ]; then
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
    # Check if the wg0 interface actually exists (most reliable)
    if ip link show wg0 >/dev/null 2>&1; then
        return 0
    fi
    # Fallback: check systemd service status
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet wg-quick@wg0
        return
    fi
    return 1
}

do_configure_wg_firewall_rules() {
    if ! grep -q '\[Interface\]' "$WG_CONF_DEST"; then
        echo "ERROR: No [Interface] section found in $WG_CONF_DEST" >> "$LOG_FILE"
        return 1
    fi

    # WireGuard PostUp/PostDown handle ONLY rules that depend on the wg0 interface
    # existing. WAN MASQUERADE must NOT be tied to wg0 lifecycle - if wg0 flaps,
    # LAN clients still need NAT to reach the upstream network. WAN MASQUERADE is
    # persisted independently via ensure_nat_rules() + netfilter-persistent.
    local POST_UP="PostUp = iptables -C FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT; iptables -C FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE"
    local POST_DOWN="PostDown = iptables -D FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null || true"

    sed -i '/^PostUp =/d' "$WG_CONF_DEST"
    sed -i '/^PostDown =/d' "$WG_CONF_DEST"

    awk -v up="$POST_UP" -v down="$POST_DOWN" '/\[Interface\]/ { print; print up; print down; next } 1' "$WG_CONF_DEST" > "${WG_CONF_DEST}.tmp" && mv "${WG_CONF_DEST}.tmp" "$WG_CONF_DEST"
}

do_start_wireguard() {
    # Skip restart if wg0 is already up and the installed config has not changed
    # since the previous run (avoids gratuitous tunnel + LAN-traffic blip).
    local installed_hash="" prev_hash="${WG_PREV_HASH:-}"
    if [ -f "$WG_CONF_DEST" ]; then
        installed_hash=$(sha256sum "$WG_CONF_DEST" | awk '{print $1}')
    fi
    if ip link show wg0 >/dev/null 2>&1 \
       && systemctl is-active --quiet wg-quick@wg0 \
       && [ -n "$installed_hash" ] && [ "$installed_hash" = "$prev_hash" ]; then
        echo "[wg] wg0 already active with matching config; skipping restart" >> "$LOG_FILE"
        systemctl enable wg-quick@wg0 >> "$LOG_FILE" 2>&1 || true
        return 0
    fi
    if ip link show wg0 >/dev/null 2>&1; then
        wg-quick down wg0 || true
    fi
    wg-quick up wg0 && systemctl enable wg-quick@wg0
}

do_configure_auto_updates() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >> "$LOG_FILE" 2>&1
    apt-get install -y unattended-upgrades >> "$LOG_FILE" 2>&1
    
    cat > /etc/apt/apt.conf.d/51unattended-upgrades-gateway <<'EOF'
Unattended-Upgrade::Origins-Pattern {
    "origin=*";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Verbose "true";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Download-Upgradeable-Packages "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Keep-Debs "false";
EOF

    cat > /etc/apt/apt.conf.d/52periodic-gateway <<'EOF'
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Verbose "1";
EOF

    systemctl enable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer >> "$LOG_FILE" 2>&1 || true
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

    # Remove FORWARD and NAT rules tied to the OLD LAN iface so re-runs don't
    # accumulate stale forwarding rules each time the interface is changed.
    if iptables -C FORWARD -i "$old_iface" -o wg0 -j ACCEPT >/dev/null 2>&1; then
        iptables -D FORWARD -i "$old_iface" -o wg0 -j ACCEPT >> "$LOG_FILE" 2>&1 || true
    fi
    if iptables -C FORWARD -i wg0 -o "$old_iface" -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
        iptables -D FORWARD -i wg0 -o "$old_iface" -m state --state RELATED,ESTABLISHED -j ACCEPT >> "$LOG_FILE" 2>&1 || true
    fi
    # Tagged INPUT rule on the old LAN (added by ensure_wan_firewall_rules) is
    # cleaned up by remove_tagged_input_rules() on the next firewall apply.

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
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# --- Progress Box System ---
# Step statuses: pending, running, done, fail, skip
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
    
    # Move cursor up to redraw if we've drawn before
    if [ "$PROGRESS_BOX_LINES" -gt 0 ]; then
        # Move up and clear each line
        for ((j=0; j<PROGRESS_BOX_LINES; j++)); do
            printf "\033[A\033[2K"
        done
    fi
    
    local lines=0
    
    # Header
    echo -e "${CYAN}╭${border}╮${NC}"
    echo -e "${CYAN}│${NC} ${BOLD}${YELLOW}⚡ Setup Progress${NC}$(printf '%*s' $((content_w - 17)) '') ${CYAN}│${NC}"
    echo -e "${CYAN}├${border}┤${NC}"
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
            echo -e "${CYAN}│${NC} ${color}${icon} ${step}${NC} ${DIM}${extra}${NC}$(printf '%*s' $padding '') ${CYAN}│${NC}"
        else
            echo -e "${CYAN}│${NC} ${color}${icon} ${step}${NC}$(printf '%*s' $padding '') ${CYAN}│${NC}"
        fi
        lines=$((lines + 1))
    done
    
    # Footer
    echo -e "${CYAN}╰${border}╯${NC}"
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
    
    # Show spinner below the box
    printf "   "
    while kill -0 $pid 2>/dev/null; do
        printf "\r   ${YELLOW}${spin_frames[$frame]}${NC} Running: ${DIM}%s${NC}   " "$step_name"
        frame=$(( (frame + 1) % ${#spin_frames[@]} ))
        sleep 0.1
    done
    # Clear the spinner line
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

progress_done_step() {
    local step_name="$1"
    local extra="${2:-}"
    local idx
    idx=$(progress_find_step "$step_name")
    [ "$idx" != "-1" ] && progress_set_status "$idx" "done" "$extra"
}

progress_clear() {
    PROGRESS_STEPS=()
    PROGRESS_STATUS=()
    PROGRESS_EXTRA=()
    PROGRESS_BOX_LINES=0
}

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

# Print Header (banner already shown by gateway-manage-or-setup.sh wrapper)
print_header() {
    echo ""
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
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
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

# Ensure iptables forwarding/NAT rules exist for LAN -> wg0 and LAN -> WAN.
# These rules are persisted to disk regardless of WAN firewall opt-in, so they
# survive reboots even if wg0 fails to come up at boot.
ensure_nat_rules() {
    echo "[ensure_nat_rules] Verifying iptables rules for $LAN_IFACE -> wg0/$WAN_IFACE" >> "$LOG_FILE"
    if ! iptables -C FORWARD -i "$LAN_IFACE" -o wg0 -j ACCEPT >/dev/null 2>&1; then
        iptables -A FORWARD -i "$LAN_IFACE" -o wg0 -j ACCEPT >> "$LOG_FILE" 2>&1
    fi
    if ! iptables -C FORWARD -i wg0 -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
        iptables -A FORWARD -i wg0 -o "$LAN_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT >> "$LOG_FILE" 2>&1
    fi
    if ! iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE >/dev/null 2>&1; then
        iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE >> "$LOG_FILE" 2>&1
    fi
    if [ -n "$WAN_IFACE" ] && ! iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE >/dev/null 2>&1; then
        iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE >> "$LOG_FILE" 2>&1
    fi
}

# Persist iptables/NAT rules to disk so they survive reboot regardless of any
# optional firewall feature toggles.
persist_iptables_rules() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        echo "[persist] Saving iptables rules via netfilter-persistent..." >> "$LOG_FILE"
        netfilter-persistent save >> "$LOG_FILE" 2>&1 || true
    elif command -v iptables-save >/dev/null 2>&1 && [ -d /etc/iptables ]; then
        echo "[persist] Saving iptables rules to /etc/iptables/rules.v4..." >> "$LOG_FILE"
        iptables-save > /etc/iptables/rules.v4 2>>"$LOG_FILE" || true
    fi
}

# --- WAN Static IP helpers ---

# Populate WAN_CURRENT_IP / WAN_CURRENT_PREFIX / WAN_GATEWAY for the given iface
detect_wan_network() {
    local iface="$1"
    WAN_CURRENT_IP=""
    WAN_CURRENT_PREFIX=""
    WAN_GATEWAY=""

    local ip_line
    ip_line=$(ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{print $4}' | head -n1)
    if [ -n "$ip_line" ]; then
        WAN_CURRENT_IP="${ip_line%/*}"
        WAN_CURRENT_PREFIX="${ip_line#*/}"
    fi

    WAN_GATEWAY=$(ip -o -4 route show default dev "$iface" 2>/dev/null | awk '{print $3}' | head -n1)
    if [ -z "$WAN_GATEWAY" ]; then
        WAN_GATEWAY=$(ip -o -4 route show default 2>/dev/null | awk '{print $3}' | head -n1)
    fi
}

# Suggest the second IP in the network range (e.g. router .1 -> suggest .2)
# Falls back to .3 if the router already occupies .2.
suggest_wan_static_ip() {
    local gateway="$1"
    local fallback_ip="$2"
    local anchor="$gateway"
    [ -z "$anchor" ] && anchor="$fallback_ip"
    if [ -z "$anchor" ]; then
        echo ""
        return
    fi

    local prefix last
    prefix=$(echo "$anchor" | awk -F'.' '{print $1"."$2"."$3}')
    last=$(echo "$anchor" | awk -F'.' '{print $4}')
    if ! echo "$prefix" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo ""
        return
    fi

    local suggestion="${prefix}.2"
    if [ "$last" = "2" ]; then
        suggestion="${prefix}.3"
    fi
    echo "$suggestion"
}

# Basic dotted-quad validation
is_valid_ipv4() {
    echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
    local oct
    for oct in $(echo "$1" | tr '.' ' '); do
        [ "$oct" -le 255 ] || return 1
    done
    return 0
}

# Does the WAN interface already have a manually-configured static address?
wan_has_static_ip() {
    local iface="$1"
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
        local con_name method
        con_name=$(nmcli -t -f NAME,DEVICE connection show | grep ":$iface$" | cut -d: -f1 | head -n1)
        if [ -n "$con_name" ]; then
            method=$(nmcli -t -f ipv4.method connection show "$con_name" 2>/dev/null | cut -d: -f2)
            [ "$method" = "manual" ] && return 0
        fi
    fi
    if [ -f /etc/dhcpcd.conf ] && \
       awk -v iface="$iface" '
           $1=="interface" && $2==iface {found=1; next}
           /^interface[[:space:]]/ && found {found=0}
           found && /static[[:space:]]+ip_address/ {print; exit}
       ' /etc/dhcpcd.conf | grep -q .; then
        return 0
    fi
    return 1
}

do_configure_wan_static_ip() {
    local iface="$WAN_IFACE"
    local ip="$WAN_STATIC_IP"
    local prefix="$WAN_STATIC_PREFIX"
    local gw="$WAN_STATIC_GATEWAY"
    local dns="$WAN_STATIC_DNS"

    if [ -z "$iface" ] || [ -z "$ip" ] || [ -z "$prefix" ]; then
        echo "[wan_static] Missing iface/ip/prefix; skipping" >> "$LOG_FILE"
        return 0
    fi

    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
        local con_name
        con_name=$(nmcli -t -f NAME,DEVICE connection show | grep ":$iface$" | cut -d: -f1 | head -n1)
        if [ -z "$con_name" ]; then
            con_name="Wired connection $iface"
            nmcli con add type ethernet ifname "$iface" con-name "$con_name" >> "$LOG_FILE" 2>&1 || true
        fi
        local dns_csv="${dns// /,}"
        nmcli con modify "$con_name" \
            ipv4.addresses "$ip/$prefix" \
            ipv4.gateway "${gw:-}" \
            ipv4.dns "$dns_csv" \
            ipv4.method manual >> "$LOG_FILE" 2>&1
        nmcli con up "$con_name" >> "$LOG_FILE" 2>&1 || true
    elif [ -f /etc/dhcpcd.conf ]; then
        sed -i '/# VPN-GATEWAY-WAN-START/,/# VPN-GATEWAY-WAN-END/d' /etc/dhcpcd.conf
        {
            echo '# VPN-GATEWAY-WAN-START'
            echo "interface $iface"
            echo "static ip_address=$ip/$prefix"
            [ -n "$gw" ] && echo "static routers=$gw"
            [ -n "$dns" ] && echo "static domain_name_servers=$dns"
            echo '# VPN-GATEWAY-WAN-END'
        } >> /etc/dhcpcd.conf
        systemctl restart dhcpcd >> "$LOG_FILE" 2>&1 || true
    else
        ip addr flush dev "$iface" >> "$LOG_FILE" 2>&1 || true
        ip addr add "$ip/$prefix" dev "$iface" >> "$LOG_FILE" 2>&1 || true
        ip link set "$iface" up >> "$LOG_FILE" 2>&1 || true
        [ -n "$gw" ] && ip route add default via "$gw" >> "$LOG_FILE" 2>&1 || true
    fi
}

# Interactive prompt: asks whether to configure a static WAN IP and collects fields.
# Sets WAN_STATIC_IP_ENABLED and (if enabled) WAN_STATIC_IP/PREFIX/GATEWAY/DNS.
prompt_wan_static_ip() {
    detect_wan_network "$WAN_IFACE"

    local already_static=false
    if wan_has_static_ip "$WAN_IFACE"; then
        already_static=true
    fi

    echo ""
    info "WAN Static IP (optional, recommended)"
    echo -e "   ${BLUE}👉 A static WAN IP ensures the Pi is always reachable at a predictable${NC}"
    echo -e "   ${BLUE}   address from the upstream network (SSH, diagnostics, port forwards).${NC}"
    if [ -n "$WAN_CURRENT_IP" ]; then
        echo -e "   ${DIM}Current IP on $WAN_IFACE: ${WAN_CURRENT_IP}/${WAN_CURRENT_PREFIX}${NC}"
    fi
    if [ -n "$WAN_GATEWAY" ]; then
        echo -e "   ${DIM}Detected gateway:        ${WAN_GATEWAY}${NC}"
    fi
    if [ "$already_static" = true ]; then
        echo -e "   ${GREEN}✔ $WAN_IFACE already appears to have a static configuration.${NC}"
    fi

    local default_yes=true
    [ "$already_static" = true ] && default_yes=false

    local prompt
    if [ "$default_yes" = true ]; then
        prompt="🔒 Configure a static IP on $WAN_IFACE? [Y/n]"
    else
        prompt="🔒 Reconfigure static IP on $WAN_IFACE? [y/N]"
    fi
    echo -ne "   $prompt: "
    read -r answer < /dev/tty

    local enabled="false"
    if [ "$default_yes" = true ]; then
        [[ "$answer" =~ ^[Nn]$ ]] || enabled="true"
    else
        [[ "$answer" =~ ^[Yy]$ ]] && enabled="true"
    fi

    WAN_STATIC_IP_ENABLED="$enabled"
    save_config_var "WAN_STATIC_IP_ENABLED" "$enabled"

    if [ "$enabled" != "true" ]; then
        info "Skipping WAN static IP configuration (will leave as-is)."
        return
    fi

    local suggestion
    suggestion=$(suggest_wan_static_ip "$WAN_GATEWAY" "$WAN_CURRENT_IP")

    local default_ip="${WAN_STATIC_IP:-$suggestion}"
    while true; do
        if [ -n "$default_ip" ]; then
            echo -ne "   📌 Static IP [default: ${BOLD}${YELLOW}${default_ip}${NC}]: "
        else
            echo -ne "   📌 Static IP: "
        fi
        read -r user_ip < /dev/tty
        [ -z "$user_ip" ] && user_ip="$default_ip"
        if is_valid_ipv4 "$user_ip"; then
            WAN_STATIC_IP="$user_ip"
            break
        fi
        warn "Not a valid IPv4 address: $user_ip"
    done

    local default_prefix="${WAN_STATIC_PREFIX:-${WAN_CURRENT_PREFIX:-24}}"
    while true; do
        echo -ne "   📐 Prefix length [default: ${BOLD}${YELLOW}${default_prefix}${NC}]: "
        read -r user_prefix < /dev/tty
        [ -z "$user_prefix" ] && user_prefix="$default_prefix"
        if echo "$user_prefix" | grep -Eq '^[0-9]+$' && [ "$user_prefix" -ge 8 ] && [ "$user_prefix" -le 32 ]; then
            WAN_STATIC_PREFIX="$user_prefix"
            break
        fi
        warn "Prefix must be an integer between 8 and 32."
    done

    local default_gateway="${WAN_STATIC_GATEWAY:-${WAN_GATEWAY}}"
    while true; do
        if [ -n "$default_gateway" ]; then
            echo -ne "   🧭 Gateway [default: ${BOLD}${YELLOW}${default_gateway}${NC}]: "
        else
            echo -ne "   🧭 Gateway: "
        fi
        read -r user_gateway < /dev/tty
        [ -z "$user_gateway" ] && user_gateway="$default_gateway"
        if [ -z "$user_gateway" ] || is_valid_ipv4 "$user_gateway"; then
            WAN_STATIC_GATEWAY="$user_gateway"
            break
        fi
        warn "Not a valid IPv4 address: $user_gateway"
    done

    local default_dns="${WAN_STATIC_DNS:-1.1.1.1 8.8.8.8}"
    echo -ne "   🌐 DNS servers (space-separated) [default: ${BOLD}${YELLOW}${default_dns}${NC}]: "
    read -r user_dns < /dev/tty
    [ -z "$user_dns" ] && user_dns="$default_dns"
    WAN_STATIC_DNS="$user_dns"

    save_config_var "WAN_STATIC_IP" "$WAN_STATIC_IP"
    save_config_var "WAN_STATIC_PREFIX" "$WAN_STATIC_PREFIX"
    save_config_var "WAN_STATIC_GATEWAY" "$WAN_STATIC_GATEWAY"
    save_config_var "WAN_STATIC_DNS" "$WAN_STATIC_DNS"

    success "Static WAN IP: $WAN_STATIC_IP/$WAN_STATIC_PREFIX via ${WAN_STATIC_GATEWAY:-<none>}"
}

# Marker used on every iptables INPUT rule installed by ensure_wan_firewall_rules
# so we can find/remove them safely on re-run (handles SSH_PORT / WG_LISTEN_PORT
# or WAN_IFACE changes without leaving stale or wrongly-ordered rules behind).
FW_RULE_TAG="vpn-gateway"

# Remove any previously-tagged INPUT rules. Safe to call before re-applying.
remove_tagged_input_rules() {
    local tag="$FW_RULE_TAG"
    # iptables-save preserves rule order; keep deleting matched lines until none.
    local saved
    saved=$(iptables-save 2>/dev/null) || return 0
    echo "$saved" | awk -v tag="$tag" '
        /^-A INPUT/ && index($0, "--comment \"" tag "\"") {
            sub(/^-A /, "-D ")
            print
        }' | while read -r rule; do
        # shellcheck disable=SC2086
        iptables $rule >> "$LOG_FILE" 2>&1 || true
    done
}

ensure_wan_firewall_rules() {
    echo "[wan_firewall] Applying hardened INPUT rules for WAN=$WAN_IFACE (tag=$FW_RULE_TAG)" >> "$LOG_FILE"
    local ssh_port="${SSH_PORT:-22}"
    local tag="$FW_RULE_TAG"

    # Wipe previous tagged rules first, so SSH_PORT/WG_LISTEN_PORT/WAN_IFACE
    # changes from a re-run don't leave stale ACCEPTs or a stranded DROP.
    remove_tagged_input_rules

    # Order matters: ACCEPT rules MUST be installed before the final DROP.
    iptables -A INPUT -i lo -m comment --comment "$tag" -j ACCEPT >> "$LOG_FILE" 2>&1
    iptables -A INPUT -i "$LAN_IFACE" -m comment --comment "$tag" -j ACCEPT >> "$LOG_FILE" 2>&1
    iptables -A INPUT -i wg0 -m comment --comment "$tag" -j ACCEPT >> "$LOG_FILE" 2>&1
    iptables -A INPUT -i "$WAN_IFACE" -m state --state RELATED,ESTABLISHED \
        -m comment --comment "$tag" -j ACCEPT >> "$LOG_FILE" 2>&1
    iptables -A INPUT -i "$WAN_IFACE" -p tcp --dport "$ssh_port" \
        -m comment --comment "$tag" -j ACCEPT >> "$LOG_FILE" 2>&1
    if [ -n "${WG_LISTEN_PORT:-}" ]; then
        iptables -A INPUT -i "$WAN_IFACE" -p udp --dport "$WG_LISTEN_PORT" \
            -m comment --comment "$tag" -j ACCEPT >> "$LOG_FILE" 2>&1
    fi
    # Final drop on WAN INPUT - always installed last so SSH ACCEPT precedes it.
    iptables -A INPUT -i "$WAN_IFACE" -m comment --comment "$tag" -j DROP >> "$LOG_FILE" 2>&1

    persist_iptables_rules
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

get_lan_device_unit() {
    local iface="${1:-$LAN_IFACE}"
    if command -v systemd-escape >/dev/null 2>&1; then
        systemd-escape --path --suffix=device "/sys/subsystem/net/devices/$iface"
    else
        echo "sys-subsystem-net-devices-${iface}.device"
    fi
}

get_interface_details() {
    local iface="$1"
    local state mac ipv4 driver devpath bus_type
    state=$(ip -br link show dev "$iface" 2>/dev/null | awk '{print $2}')
    [ -z "$state" ] && state="UNKNOWN"

    ipv4=$(ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{print $4}' | paste -sd, -)
    [ -z "$ipv4" ] && ipv4="none"

    mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null)
    [ -z "$mac" ] && mac="unknown"

    if [ -L "/sys/class/net/$iface/device/driver" ]; then
        driver=$(basename "$(readlink "/sys/class/net/$iface/device/driver")")
    else
        driver="unknown"
    fi

    if [ -L "/sys/class/net/$iface/device" ]; then
        devpath=$(readlink "/sys/class/net/$iface/device")
        case "$devpath" in
            *"/usb"/*|*"usb"* ) bus_type="usb" ;;
            *"/pci"* ) bus_type="pci" ;;
            * ) bus_type="onboard" ;;
        esac
    else
        bus_type="virtual"
    fi

    echo "state=$state  ipv4=$ipv4"
    echo "mac=$mac  driver=$driver  bus=$bus_type"
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
        local detail_line1 detail_line2
        detail_line1=$(get_interface_details "$iface" | sed -n '1p')
        detail_line2=$(get_interface_details "$iface" | sed -n '2p')
        printf "   %2d) %s\n" "$idx" "$iface" >&2
        printf "       ${DIM}%s${NC}\n" "$detail_line1" >&2
        printf "       ${DIM}%s${NC}\n" "$detail_line2" >&2
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

do_configure_lan_ready_service() {
    local lan_device_unit
    lan_device_unit=$(get_lan_device_unit "$LAN_IFACE")

    # BindsTo only for USB NICs (transient disappearance) - same policy as drop-ins.
    local lan_bus_type=""
    lan_bus_type=$(get_interface_details "$LAN_IFACE" 2>/dev/null \
                   | sed -n '2p' | sed -n 's/.*bus=\([^ ]*\).*/\1/p')
    local binds_line=""
    if [ "$lan_bus_type" = "usb" ]; then
        binds_line="BindsTo=${lan_device_unit}"
    fi

    local before_services="dnsmasq.service wg-quick@wg0.service"
    local pre_cmd=""
    if [ "${IS_WIRELESS:-false}" = "true" ]; then
        before_services="dnsmasq.service hostapd.service wg-quick@wg0.service"
        pre_cmd="ExecStartPre=/bin/bash -c '/usr/sbin/rfkill unblock wlan || true'"
    fi

    {
        printf '[Unit]\n'
        printf 'Description=VPN Gateway LAN Interface Setup\n'
        printf 'Wants=%s\n' "$lan_device_unit"
        printf 'After=%s\n' "$lan_device_unit"
        [ -n "$binds_line" ] && printf '%s\n' "$binds_line"
        printf 'Before=%s\n' "$before_services"
        printf '\n[Service]\n'
        printf 'Type=oneshot\n'
        printf 'RemainAfterExit=yes\n'
        [ -n "$pre_cmd" ] && printf '%s\n' "$pre_cmd"
        # Robust IP existence check: exact /24 match, not substring.
        printf "ExecStart=/bin/bash -c 'ip -4 -o addr show dev %s scope global 2>/dev/null | awk \"{print \\\$4}\" | grep -qx %s/24 || ip addr add %s/24 dev %s'\n" \
            "$LAN_IFACE" "$LAN_GATEWAY" "$LAN_GATEWAY" "$LAN_IFACE"
        printf 'ExecStart=/bin/ip link set %s up\n' "$LAN_IFACE"
        printf '\n[Install]\n'
        printf 'WantedBy=multi-user.target\n'
    } > /etc/systemd/system/vpn-gateway-lan.service

    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || true
    systemctl enable vpn-gateway-lan.service >> "$LOG_FILE" 2>&1 || true
    systemctl restart vpn-gateway-lan.service >> "$LOG_FILE" 2>&1 || true
}

lan_iface_has_gateway_ip() {
    # Exact /24 match - not substring.
    ip -4 -o addr show dev "$LAN_IFACE" scope global 2>/dev/null \
        | awk '{print $4}' | grep -qx "$LAN_GATEWAY/24"
}

# Collect any user confirmations needed because of SSH-disconnect risk during
# install. MUST be called during the input-collection phase only - never during
# execution - so the run can proceed unattended once started.
prompt_ssh_safety_warnings() {
    SSH_DISCONNECT_ACK="false"
    SSH_IFACE="$(detect_ssh_iface)"

    if [ -z "$SSH_IFACE" ]; then
        return 0
    fi

    local wan_static_planned="${WAN_STATIC_IP_ENABLED:-false}"
    local lan_will_change=true
    if lan_iface_has_gateway_ip; then
        lan_will_change=false
    fi

    local risk=false risk_lines=()
    if [ "$SSH_IFACE" = "$LAN_IFACE" ] && [ "$lan_will_change" = true ]; then
        risk=true
        risk_lines+=("• Your SSH session is on the planned LAN interface ($SSH_IFACE).")
        risk_lines+=("  The LAN interface will be reconfigured to $LAN_GATEWAY/24 - this WILL drop your SSH session.")
    fi
    if [ "$SSH_IFACE" = "$WAN_IFACE" ] && [ "$wan_static_planned" = "true" ]; then
        risk=true
        risk_lines+=("• Your SSH session is on the WAN interface ($SSH_IFACE).")
        risk_lines+=("  WAN static IP reassignment to $WAN_STATIC_IP/$WAN_STATIC_PREFIX WILL drop your SSH session.")
        risk_lines+=("  Reconnect after install at: ssh <user>@$WAN_STATIC_IP")
    fi

    if [ "$risk" = false ]; then
        SSH_DISCONNECT_ACK="true"
        return 0
    fi

    echo ""
    warn "SSH disconnect risk detected:"
    local line
    for line in "${risk_lines[@]}"; do
        echo -e "   ${YELLOW}${line}${NC}"
    done
    echo ""
    if [ "$NONINTERACTIVE" = "true" ]; then
        info "Non-interactive: proceeding (the operator must reconnect manually if SSH drops)."
        SSH_DISCONNECT_ACK="true"
        return 0
    fi
    echo -ne "❓ ${YELLOW}Acknowledge and continue? Setup will run unattended. [y/N]:${NC} "
    read -r ack < /dev/tty
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        SSH_DISCONNECT_ACK="true"
    else
        error "Aborted by user (SSH disconnect risk not acknowledged)."
        exit 1
    fi
}

do_configure_lan_interface() {
    # Idempotent: if the LAN already has the correct gateway IP, do not flush.
    # This preserves any in-flight SSH session over the LAN interface on re-runs.
    local already_configured=false
    if lan_iface_has_gateway_ip; then
        already_configured=true
        echo "[lan] $LAN_IFACE already has $LAN_GATEWAY/24; skipping flush" >> "$LOG_FILE"
    fi

    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
        if [ "$IS_WIRELESS" = true ]; then
            if [ "$already_configured" != true ]; then
                ip addr flush dev "$LAN_IFACE" 2>/dev/null || true
                ip addr add "$LAN_GATEWAY/24" dev "$LAN_IFACE" 2>/dev/null || true
            fi
            ip link set "$LAN_IFACE" up
        else
            local con_name
            con_name=$(nmcli -t -f NAME,DEVICE connection show | grep ":$LAN_IFACE$" | cut -d: -f1 | head -n1)
            if [ -z "$con_name" ]; then
                con_name="Wired connection $LAN_IFACE"
                nmcli con add type ethernet ifname "$LAN_IFACE" con-name "$con_name" >> "$LOG_FILE" 2>&1 || true
            fi
            local current_method current_addr
            current_method=$(nmcli -t -f ipv4.method connection show "$con_name" 2>/dev/null | cut -d: -f2)
            current_addr=$(nmcli -t -f ipv4.addresses connection show "$con_name" 2>/dev/null | cut -d: -f2)
            if [ "$current_method" != "manual" ] || [ "$current_addr" != "$LAN_GATEWAY/24" ]; then
                nmcli con modify "$con_name" ipv4.addresses "$LAN_GATEWAY/24" ipv4.method manual >> "$LOG_FILE" 2>&1
                nmcli con up "$con_name" >> "$LOG_FILE" 2>&1 || true
            else
                echo "[lan] NM connection '$con_name' already configured; skipping" >> "$LOG_FILE"
            fi
        fi
    elif [ -f /etc/dhcpcd.conf ]; then
        if grep -q '# VPN-GATEWAY-START' /etc/dhcpcd.conf \
           && grep -A2 '# VPN-GATEWAY-START' /etc/dhcpcd.conf | grep -q "interface $LAN_IFACE" \
           && grep -A3 '# VPN-GATEWAY-START' /etc/dhcpcd.conf | grep -q "static ip_address=$LAN_GATEWAY/24"; then
            echo "[lan] dhcpcd stanza already correct; skipping" >> "$LOG_FILE"
        else
            sed -i '/# VPN-GATEWAY-START/,/# VPN-GATEWAY-END/d' /etc/dhcpcd.conf
            {
                echo '# VPN-GATEWAY-START'
                echo "interface $LAN_IFACE"
                echo "static ip_address=$LAN_GATEWAY/24"
                echo 'nohook wpa_supplicant'
                echo '# VPN-GATEWAY-END'
            } >> /etc/dhcpcd.conf
            systemctl restart dhcpcd >> "$LOG_FILE" 2>&1 || true
        fi
    else
        if [ "$already_configured" != true ]; then
            ip addr flush dev "$LAN_IFACE" 2>/dev/null || true
            ip addr add "$LAN_GATEWAY/24" dev "$LAN_IFACE"
        fi
        ip link set "$LAN_IFACE" up
    fi

    do_configure_lan_ready_service
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

    # --- First prompt: System dependencies (required) ---
    # Check which packages are missing (must check for "install ok installed" status, not just dpkg -s exit code)
    is_pkg_installed() {
        dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
    }
    MISSING_PKGS=""
    if ! is_pkg_installed wireguard; then MISSING_PKGS="$MISSING_PKGS wireguard"; fi
    if ! is_pkg_installed dnsmasq; then MISSING_PKGS="$MISSING_PKGS dnsmasq"; fi
    if ! is_pkg_installed iptables; then MISSING_PKGS="$MISSING_PKGS iptables"; fi
    if ! is_pkg_installed qrencode; then MISSING_PKGS="$MISSING_PKGS qrencode"; fi
    if ! is_pkg_installed resolvconf; then MISSING_PKGS="$MISSING_PKGS resolvconf"; fi
    if ! is_pkg_installed iptables-persistent; then MISSING_PKGS="$MISSING_PKGS iptables-persistent"; fi

    if [ -n "$MISSING_PKGS" ]; then
        # If using existing config with INSTALL_DEPENDENCIES already set, skip prompt
        if [ "$USE_EXISTING_CONFIG" = true ] && [ "${INSTALL_DEPENDENCIES:-}" = "true" ]; then
            info "Will install missing packages:$MISSING_PKGS"
        else
            info "System Dependencies Check"
            echo -e "   ${YELLOW}Missing packages:${NC}$MISSING_PKGS"
            echo -ne "📦 ${YELLOW}Install required system packages?$MISSING_PKGS [Y/n]${NC} "
            read -r install_choice
            if [[ "$install_choice" =~ ^[Nn]$ ]]; then
                error "Package installation is required to proceed. Exiting."
                exit 1
            fi
            INSTALL_DEPENDENCIES="true"
            save_config_var "INSTALL_DEPENDENCIES" "true"
        fi
        echo ""
    else
        INSTALL_DEPENDENCIES="false"
        save_config_var "INSTALL_DEPENDENCIES" "false"
        success "All base dependencies are already installed."
        echo ""
    fi

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
        
        # Check if hostapd is needed for wireless configs (will install later with other deps)
        if [ "$IS_WIRELESS" = "true" ] || [ "$IS_WIRELESS" = true ]; then
            if ! is_pkg_installed hostapd; then
                # If already confirmed in config, skip prompt
                if [ "${INSTALL_HOSTAPD:-}" = "true" ]; then
                    info "Will install hostapd for Access Point."
                else
                    info "Wireless LAN requires hostapd (not installed)."
                    echo -ne "❓ ${YELLOW}Install hostapd for Access Point? [Y/n]${NC} "
                    read -r ap_install_choice
                    if [[ "$ap_install_choice" =~ ^[Nn]$ ]]; then
                        error "Cannot proceed with wireless LAN without hostapd. Exiting."
                        exit 1
                    fi
                    INSTALL_HOSTAPD="true"
                    save_config_var "INSTALL_HOSTAPD" "true"
                fi
            else
                INSTALL_HOSTAPD="false"
                save_config_var "INSTALL_HOSTAPD" "false"
            fi
        fi
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
            
            if is_pkg_installed hostapd; then
                 success "'hostapd' is already installed."
                 INSTALL_HOSTAPD="false"
                 save_config_var "INSTALL_HOSTAPD" "false"
            else
                echo -ne "❓ ${YELLOW}Do you want to proceed with installing hostapd? [Y/n]${NC} "
                read -r ap_install_choice
                if [[ "$ap_install_choice" =~ ^[Nn]$ ]]; then
                    error "Cannot proceed with wireless LAN without hostapd. Exiting."
                    exit 1
                fi
                INSTALL_HOSTAPD="true"
                save_config_var "INSTALL_HOSTAPD" "true"
            fi

            # Pre-fill SSID from config
            default_ssid="${AP_SSID:-}"
            prompt_ssid="📡 Enter SSID (Network Name) for the AP"
            if [ -n "$default_ssid" ]; then
                 prompt_ssid="$prompt_ssid [default: ${BOLD}${YELLOW}$default_ssid${NC}]"
            fi
            
            while true; do
                echo -ne "$prompt_ssid: "
                read -r input_ssid
                if [ -z "$input_ssid" ] && [ -n "$default_ssid" ]; then
                    AP_SSID="$default_ssid"
                    break
                elif [ -n "$input_ssid" ]; then
                    # Validate SSID: 1-32 characters, no control characters or quotes
                    if [ ${#input_ssid} -gt 32 ]; then
                        warn "SSID must be 32 characters or less."
                        continue
                    fi
                    # Check for problematic characters (quotes, backslashes, control chars)
                    if echo "$input_ssid" | grep -qE '["\x27\\]|[[:cntrl:]]'; then
                        warn "SSID cannot contain quotes, backslashes, or control characters."
                        continue
                    fi
                    AP_SSID="$input_ssid"
                    break
                else
                    warn "SSID cannot be empty."
                fi
            done
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
                elif [ ${#input_pass} -lt 8 ]; then
                    warn "Password must be at least 8 characters."
                    echo "[DEBUG] Password too short." >> "$LOG_FILE"
                    continue
                elif [ ${#input_pass} -gt 63 ]; then
                    warn "Password must be 63 characters or less."
                    echo "[DEBUG] Password too long." >> "$LOG_FILE"
                    continue
                fi
                # Check for problematic characters (quotes, backslashes, control chars)
                if echo "$input_pass" | grep -qE '["\x27\\]|[[:cntrl:]]'; then
                    warn "Password cannot contain quotes, backslashes, or control characters."
                    echo "[DEBUG] Password contains invalid characters." >> "$LOG_FILE"
                    continue
                fi
                AP_PASS="$input_pass"
                break
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
        WAN_STATIC_IP_ENABLED="${WAN_STATIC_IP_ENABLED:-false}"
    else
        # Optional: configure a static IP on the WAN interface (recommended)
        if [ "$NONINTERACTIVE" = "true" ]; then
            WAN_STATIC_IP_ENABLED="${WAN_STATIC_IP_ENABLED:-false}"
            save_config_var "WAN_STATIC_IP_ENABLED" "$WAN_STATIC_IP_ENABLED"
        else
            prompt_wan_static_ip
        fi

        # Ask whether to configure firewall (WAN hardening)
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
        echo -ne "🛠️  Enable hardware watchdog (kernel-level auto-reboot on system hang)? [Y/n]: "
        read -r watchdog_choice
        if [[ "$watchdog_choice" =~ ^[Nn]$ ]]; then
            WATCHDOG_ENABLED="false"
        else
            WATCHDOG_ENABLED="true"
        fi
        save_config_var "WATCHDOG_ENABLED" "$WATCHDOG_ENABLED"
    fi

    # SSH-safety check is the LAST input-phase step. After this, no prompts
    # may appear until "Setup Complete". The script must run unattended so the
    # operator can leave the session even if SSH is about to drop.
    prompt_ssh_safety_warnings

    echo ""
    
    # --- Build Progress Steps ---
    progress_clear
    
    # Build package list for display (include hostapd if needed)
    local display_pkgs="$MISSING_PKGS"
    if [ "${INSTALL_HOSTAPD:-}" = "true" ]; then
        display_pkgs="$display_pkgs hostapd"
        MISSING_PKGS="$MISSING_PKGS hostapd"
        INSTALL_DEPENDENCIES="true"
    fi
    
    # Add steps based on configuration
    if [ "$INSTALL_DEPENDENCIES" = "true" ] && [ -n "$display_pkgs" ]; then
        progress_add_step "Install packages" "($display_pkgs)"
    fi
    
    progress_add_step "Install WireGuard config" "→ $WG_CONF_DEST"
    progress_add_step "Enable IP forwarding"
    if [ "${WAN_STATIC_IP_ENABLED:-false}" = "true" ]; then
        progress_add_step "Configure WAN static IP" "$WAN_IFACE = ${WAN_STATIC_IP}/${WAN_STATIC_PREFIX}"
    fi
    progress_add_step "Configure LAN interface" "$LAN_IFACE = $LAN_GATEWAY"
    progress_add_step "Configure DHCP server" "(dnsmasq)"
    
    if [ "$IS_WIRELESS" = true ]; then
        progress_add_step "Configure Access Point" "(hostapd: $AP_SSID)"
    fi
    
    progress_add_step "Configure firewall & NAT"
    progress_add_step "Start WireGuard VPN"
    
    if [ "$AUTO_UPDATES_ENABLED" = "true" ]; then
        progress_add_step "Enable auto-updates" "(nightly @ 03:00)"
    fi
    
    progress_add_step "Configure service watchdog"
    
    if [ "$WATCHDOG_ENABLED" = "true" ]; then
        progress_add_step "Enable hardware watchdog"
    fi
    
    # Draw initial progress box
    progress_draw_box
    
    echo ""
    if [ "$NONINTERACTIVE" = "true" ] && [ "$USE_EXISTING_CONFIG" = true ]; then
        info "Non-interactive mode: applying changes without confirmation."
        APPLYING_CHANGES=true
    else
        echo -ne "${BOLD}Proceed with setup? [Y/n]:${NC} "
        read -r proceed_choice
        if [[ "$proceed_choice" =~ ^[Nn]$ ]]; then
            warn "Aborting setup by user request."
            exit 1
        fi
        APPLYING_CHANGES=true
    fi
    
    # Reset box line count - the prompt invalidated our cursor position
    PROGRESS_BOX_LINES=0
    echo ""
    
    # --- Execute Steps ---
    
    # Install dependencies
    if [ "$INSTALL_DEPENDENCIES" = "true" ] && [ -n "$MISSING_PKGS" ]; then
        progress_run_step "Install packages" "
            apt-get update && \
            echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | debconf-set-selections 2>/dev/null || true && \
            echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | debconf-set-selections 2>/dev/null || true && \
            echo 'watchdog watchdog/run boolean true' | debconf-set-selections 2>/dev/null || true && \
            echo 'watchdog watchdog/module string bcm2835_wdt' | debconf-set-selections 2>/dev/null || true && \
            DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confold' $MISSING_PKGS
        "
    fi
    
    # Capture hash of currently-installed wg config (used by do_start_wireguard
    # to decide whether wg0 needs a restart at all).
    WG_PREV_HASH=""
    if [ -f "$WG_CONF_DEST" ]; then
        WG_PREV_HASH=$(sha256sum "$WG_CONF_DEST" | awk '{print $1}')
    fi

    # Install WireGuard config
    progress_run_step "Install WireGuard config" "cp \"$WG_CONF_SRC\" \"$WG_CONF_DEST\" && chmod 600 \"$WG_CONF_DEST\""
    
    # Enable IP forwarding
    progress_run_step "Enable IP forwarding" "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn-gateway.conf && sysctl -p /etc/sysctl.d/99-vpn-gateway.conf"

    # Configure WAN static IP (optional)
    if [ "${WAN_STATIC_IP_ENABLED:-false}" = "true" ]; then
        progress_run_step "Configure WAN static IP" "do_configure_wan_static_ip"
    fi

    # Configure LAN interface
    progress_run_step "Configure LAN interface" "do_configure_lan_interface"
    
    # Configure dnsmasq
    # Backup original /etc/dnsmasq.conf only the first time so re-runs do not
    # overwrite the genuine original (cleanup relies on this to restore state).
    progress_run_step "Configure DHCP server" "
        if [ ! -f /etc/dnsmasq.conf.bak ] && [ -f /etc/dnsmasq.conf ]; then
            cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
        fi
        cat > /etc/dnsmasq.conf <<DNSMASQ_EOF
# Managed by raspberrypi-site2site-wireguard setup-vpn-gateway.sh
interface=$LAN_IFACE
except-interface=lo
except-interface=$WAN_IFACE
bind-dynamic
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h
dhcp-option=option:dns-server,$LAN_GATEWAY
dhcp-option=option:router,$LAN_GATEWAY
DNSMASQ_EOF
        systemctl restart dnsmasq
        systemctl enable dnsmasq
    "
    
    # Configure hostapd if wireless
    if [ "$IS_WIRELESS" = true ]; then
        progress_run_step "Configure Access Point" "
            mkdir -p /etc/hostapd
            cat > /etc/hostapd/hostapd.conf <<HOSTAPD_EOF
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
wpa_pairwise=CCMP
rsn_pairwise=CCMP
HOSTAPD_EOF
            sed -i 's|#DAEMON_CONF=\"\"|DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"|' /etc/default/hostapd 2>/dev/null || true
            rfkill unblock wlan 2>/dev/null || true
            systemctl unmask hostapd
            systemctl enable hostapd
            systemctl restart hostapd
        "
    fi
    
    # Configure firewall
    progress_run_step "Configure firewall & NAT" "do_configure_wg_firewall_rules"
    
    # Start WireGuard
    progress_run_step "Start WireGuard VPN" "do_start_wireguard"

    # Enforce required NAT/forward rules (runs silently as part of firewall step)
    ensure_nat_rules
    if [ "$FIREWALL_ENABLED" = "true" ]; then
        ensure_wan_firewall_rules
    else
        echo "[wan_firewall] Skipped (user disabled)" >> "$LOG_FILE"
    fi
    # Always persist iptables/NAT to disk regardless of WAN firewall toggle so
    # forwarding/MASQUERADE survives reboot even if wg0 fails to come up.
    persist_iptables_rules

    # Auto-updates
    if [ "$AUTO_UPDATES_ENABLED" = "true" ]; then
        progress_run_step "Enable auto-updates" "do_configure_auto_updates"
    fi

    # Software watchdog (always enabled)
    progress_run_step "Configure service watchdog" "do_software_watchdog_setup"

    # Hardware watchdog (optional)
    if [ "$WATCHDOG_ENABLED" = "true" ]; then
        progress_run_step "Enable hardware watchdog" "do_hardware_watchdog_setup"
    fi
    
    # Final redraw to show all complete
    progress_draw_box

    echo ""
    echo -e "${GREEN}${BOLD}🎉 Setup Complete!${NC}"
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
