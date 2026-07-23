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

# Detect whether Raspberry Pi Connect (or a similar remote-management daemon
# that depends on outbound Internet) is running. Pi Connect uses a userspace
# WebRTC client that needs the Pi's default route to reach Raspberry Pi's
# relay; anything that hijacks the default route (e.g. WireGuard with
# AllowedIPs = 0.0.0.0/0) will tear its session down.
#
# Returns 0 if active, 1 otherwise. Echoes a short label on success.
detect_pi_connect_active() {
    # Active systemd unit (system or user scope) is the most reliable signal.
    if systemctl is-active --quiet rpi-connect 2>/dev/null \
       || systemctl --user is-active --quiet rpi-connect 2>/dev/null; then
        echo "rpi-connect"
        return 0
    fi
    # Fallback: a process whose name matches rpi-connect / rpi-connect-wayvnc.
    if pgrep -f 'rpi-connect(-wayvnc)?' >/dev/null 2>&1; then
        echo "rpi-connect"
        return 0
    fi
    return 1
}

# Extract every AllowedIPs entry from the WireGuard config that is NOT a
# default-route catch-all. These are the "home" subnets that must be
# explicitly routable via wg0 in BOTH the main table (so the Pi itself can
# reach them) and the wgvpn table (so LAN clients also reach them).
#
# Echoes one CIDR per line. Empty output is valid (no specific subnets).
extract_home_subnets() {
    local cfg="$1"
    [ -f "$cfg" ] || return 0
    awk '
        /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "", $0)
            n = split($0, parts, ",")
            for (i = 1; i <= n; i++) {
                gsub(/[[:space:]]/, "", parts[i])
                if (parts[i] == "" \
                    || parts[i] == "0.0.0.0/0" \
                    || parts[i] == "::/0" \
                    || parts[i] == "0.0.0.0/1" \
                    || parts[i] == "128.0.0.0/1") continue
                print parts[i]
            }
        }
    ' "$cfg" | sort -u
}

# Decide if a CIDR is IPv6 (contains ":") or IPv4. Echoes "6" or "4".
cidr_family() {
    case "$1" in
        *:*) echo 6 ;;
        *)   echo 4 ;;
    esac
}

# Suggest a default home DNS server: the .1 of the first IPv4 home subnet.
# Echoes empty string if no IPv4 home subnet was found in wg0.conf.
suggest_home_dns_default() {
    local cfg="$1"
    [ -f "$cfg" ] || return 0
    local cidr base
    while IFS= read -r cidr; do
        [ "$(cidr_family "$cidr")" = "4" ] || continue
        base=$(echo "$cidr" | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3}')
        if echo "$base" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "${base}.1"
            return 0
        fi
    done < <(extract_home_subnets "$cfg")
}

# Extract DNS= values from a WireGuard config (Interface section).
# wg-quick uses these to rewrite the *host* resolv.conf when the tunnel is
# up - that is client-mode semantics. On this gateway, LAN clients get DNS
# from dnsmasq (HOME_DNS_*) and the Pi itself uses PI_DNS_SERVERS via WAN,
# so DNS= is NOT applied under Pi-bypass. The values are still useful as a
# suggestion for HOME_DNS_MODE=custom (home Pi-hole / router resolver).
# Echoes a space-separated list of IPv4/IPv6 addresses (may be empty).
extract_wg_dns_servers() {
    local cfg="$1"
    [ -f "$cfg" ] || return 0
    local raw
    raw=$(awk '
        BEGIN { in_iface=0 }
        /^\[/ { in_iface = ($0 ~ /^\[Interface\]/) }
        in_iface && /^[[:space:]]*DNS[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "", $0)
            gsub(/[[:space:]]/, "", $0)
            # Drop inline comments
            sub(/#.*$/, "", $0)
            if ($0 != "") print $0
        }
    ' "$cfg" | tr ',' ' ')
    normalize_ip_list "$raw"
}

# Normalize a free-form IP list (comma- or space-separated) into a single
# space-separated, deduplicated list of valid IPv4/IPv6 addresses. Invalid
# entries are silently dropped; the caller is expected to surface them.
normalize_ip_list() {
    local raw="$1"
    [ -z "$raw" ] && return 0
    echo "$raw" | tr ',' ' ' | tr -s ' ' '\n' \
        | awk '
            # IPv4 dotted-quad
            /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
                ok=1
                n = split($0, p, ".")
                for (i = 1; i <= n; i++) if (p[i] < 0 || p[i] > 255) ok=0
                if (ok) print
                next
            }
            # IPv6: at least one colon, only hex digits + colons (no zone id)
            /:/ && /^[0-9a-fA-F:]+$/ {
                # Must not be only colons; must look like an address
                if ($0 ~ /[0-9a-fA-F]/ && $0 !~ /:::|::::/) print tolower($0)
                next
            }
          ' \
        | awk '!seen[$0]++' \
        | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

# Convert IPv4 dotted-quad to a 32-bit unsigned integer (for prefix-match math).
ipv4_to_uint() {
    local ip="$1"
    echo "$ip" | awk -F'.' '{ printf "%u", $1*16777216 + $2*65536 + $3*256 + $4 }'
}

# Test whether IPv4 $ip falls within IPv4 CIDR $cidr (e.g. "10.33.33.0/24").
# Returns 0 (true) on match, 1 otherwise. Silently returns 1 on garbage input.
ipv4_in_cidr() {
    local ip="$1" cidr="$2"
    local net prefix mask ip_int net_int
    net="${cidr%/*}"
    prefix="${cidr#*/}"
    case "$cidr" in *":"*) return 1 ;; esac
    case "$net"  in *":"*) return 1 ;; esac
    [ -z "$prefix" ] && prefix=32
    case "$prefix" in *[!0-9]*) return 1 ;; esac
    [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ] || return 1
    if [ "$prefix" = "0" ]; then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi
    ip_int=$(ipv4_to_uint "$ip")
    net_int=$(ipv4_to_uint "$net")
    [ $(( ip_int & mask )) -eq $(( net_int & mask )) ]
}

# Detect default-route AllowedIPs in the user's WireGuard config.
# Returns 0 (and echoes a short reason) if the config will redirect the Pi's
# entire outbound traffic into the tunnel, which is the single most common
# way a remote-managed Pi loses its management plane after wg-quick up.
detect_wg_default_route() {
    local cfg="$1"
    [ -f "$cfg" ] || return 1

    # Look at every AllowedIPs line; split on commas; trim whitespace; check
    # for any of: 0.0.0.0/0, ::/0, or the 0.0.0.0/1 + 128.0.0.0/1 split-default
    # trick used by some VPN configs to bypass policy routing.
    # Echoes a human-readable summary listing every match found (so callers can
    # tell IPv4-default apart from IPv6-default).
    awk '
        BEGIN { has_lo=0; has_hi=0; has_v4=0; has_v6=0 }
        /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "", $0)
            n = split($0, parts, ",")
            for (i = 1; i <= n; i++) {
                gsub(/[[:space:]]/, "", parts[i])
                if (parts[i] == "0.0.0.0/0") has_v4=1
                if (parts[i] == "::/0") has_v6=1
                if (parts[i] == "0.0.0.0/1") has_lo=1
                if (parts[i] == "128.0.0.0/1") has_hi=1
            }
        }
        END {
            out=""
            if (has_v4) out = out (out==""?"":", ") "default-route (0.0.0.0/0)"
            if (has_lo && has_hi) out = out (out==""?"":", ") "split-default-route (0.0.0.0/1 + 128.0.0.0/1)"
            if (has_v6) out = out (out==""?"":", ") "default-route (::/0)"
            if (out != "") { print out; exit 0 }
            exit 1
        }
    ' "$cfg"
}

# FD used for the progress spinner / box after become_unattended. Empty means
# "use stdout" (pre-detach, or when no TTY was available). Kept as a plain
# variable (not exported) so child shells do not inherit a stale FD number.
PROGRESS_UI_FD=""

# Write to the operator's progress TTY when detached; otherwise stdout.
# Failures are ignored so a dead TTY cannot abort the unattended run.
ui_printf() {
    if [ -n "${PROGRESS_UI_FD:-}" ]; then
        # shellcheck disable=SC2059
        printf "$@" >&"$PROGRESS_UI_FD" 2>/dev/null || true
    else
        # shellcheck disable=SC2059
        printf "$@"
    fi
}

ui_echo() {
    if [ -n "${PROGRESS_UI_FD:-}" ]; then
        echo -e "$@" >&"$PROGRESS_UI_FD" 2>/dev/null || true
    else
        echo -e "$@"
    fi
}

# Make this script survive a hangup of its controlling terminal (SSH drop,
# Pi Connect WebRTC failure, serial console close, etc.) so that the
# execution phase can finish unattended after every interactive prompt has
# already been answered.
#
# Mechanics:
#   1. trap '' HUP            -> ignore SIGHUP. Inherited (as ignored) by all
#                                 child processes via fork+exec, so wg-quick,
#                                 systemctl, apt-get, dnsmasq restarts, etc.
#                                 will not be killed if the operator's TTY
#                                 disappears.
#   2. exec </dev/null        -> any later read would block forever on a dead
#                                 TTY; close stdin to fail-fast instead.
#   3. exec >>"$LOG_FILE" 2>&1 -> redirect this script's own stdout/stderr to
#                                 the log file. Subsequent writes can no
#                                 longer hit a closed pty (which would fail
#                                 with EIO and abort the script).
#   4. Keep PROGRESS_UI_FD open on the original TTY so the progress box and
#                                 spinner can redraw cleanly. Detailed command
#                                 output (apt, systemctl, wg-quick) stays in
#                                 the log ONLY - we deliberately do NOT
#                                 auto-tail the full log onto the TTY, because
#                                 that interleaves with the spinner and makes
#                                 the UI unreadable. Operators who want the
#                                 raw stream can `tail -f` the log themselves.
#
# After this function returns, NOTHING in the script may prompt the user.
become_unattended() {
    if [ "${VPN_GATEWAY_DETACHED:-0}" = "1" ]; then
        return 0
    fi

    local tty_dev=""
    tty_dev=$(tty 2>/dev/null) || tty_dev=""

    echo ""
    if [ -n "$tty_dev" ] && [ "$tty_dev" != "not a tty" ]; then
        info "Input collected. Switching to unattended mode - setup will continue even if your connection drops."
        info "Progress stays on this terminal; detailed command output goes only to:"
        info "  $LOG_FILE"
        info "Optional detail stream:  tail -f $LOG_FILE"
        info "After reconnecting, check status with: systemctl is-active vpn-gateway-lan dnsmasq wg-quick@wg0"
        echo ""
        sleep 1
    fi

    trap '' HUP
    exec </dev/null

    mkdir -p "$(dirname "$LOG_FILE")"
    : >> "$LOG_FILE"

    # Hold an open FD on the operator's TTY for the progress UI. Do not mirror
    # the full log here - apt/wg-quick noise would fight the spinner.
    PROGRESS_UI_FD=""
    if [ -n "$tty_dev" ] && [ "$tty_dev" != "not a tty" ] && [ -w "$tty_dev" ]; then
        exec 3>"$tty_dev"
        PROGRESS_UI_FD=3
    fi

    exec >>"$LOG_FILE" 2>&1

    export VPN_GATEWAY_DETACHED=1
    echo ""
    echo "================================================================"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Entered unattended execution phase"
    echo "================================================================"
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
    prompt_q "❓ Fix WireGuard config permissions?"
    prompt_h "$path is currently $mode $owner:$group."
    prompt_h "Recommended: 600 root:root (private key material)."
    prompt_cue "[Y/n]"
    if [[ ! "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
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

# Numeric routing table + ip rule priority used by Pi-bypass mode.
# Kept as constants here AND referenced from cleanup-gateway.sh - keep in sync.
WG_BYPASS_TABLE_ID=200
WG_BYPASS_RULE_PRIO=100

# Build the iptables FORWARD/MASQUERADE Up/Down commands shared by both modes.
# Echoes one command per line.
_wg_iptables_up_cmds() {
    cat <<EOF
iptables -C FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT
iptables -C FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
EOF
}

_wg_iptables_down_cmds() {
    cat <<EOF
iptables -D FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null || true
EOF
}

# Build PostUp/PostDown commands for Pi-bypass routing. Each command runs
# under wg-quick's `set -e` semantics, so anything that may legitimately
# already exist must be guarded with `|| true` or a `-C` precheck.
#
# Routing model:
#   - main table: default via WAN gw (untouched), $home_subnets dev wg0
#     (so the Pi itself can reach the home network via the tunnel)
#   - table $WG_BYPASS_TABLE_ID: default dev wg0, $home_subnets dev wg0
#   - ip rule: forwarded packets (iif=$LAN_IFACE) -> table $WG_BYPASS_TABLE_ID
_wg_pi_bypass_up_cmds() {
    local v4="$1" v6="$2"
    local tbl="$WG_BYPASS_TABLE_ID" prio="$WG_BYPASS_RULE_PRIO"
    local s
    echo "ip route replace default dev %i table $tbl"
    for s in $v4; do
        echo "ip route replace $s dev %i"
        echo "ip route replace $s dev %i table $tbl"
    done
    echo "(ip rule list | grep -q 'iif $LAN_IFACE lookup $tbl') || ip rule add iif $LAN_IFACE lookup $tbl priority $prio"
    if [ -n "$v6" ]; then
        echo "ip -6 route replace ::/0 dev %i table $tbl"
        for s in $v6; do
            echo "ip -6 route replace $s dev %i"
            echo "ip -6 route replace $s dev %i table $tbl"
        done
        echo "(ip -6 rule list | grep -q 'iif $LAN_IFACE lookup $tbl') || ip -6 rule add iif $LAN_IFACE lookup $tbl priority $prio"
    fi
}

_wg_pi_bypass_down_cmds() {
    local v4="$1" v6="$2"
    local tbl="$WG_BYPASS_TABLE_ID" prio="$WG_BYPASS_RULE_PRIO"
    local s
    if [ -n "$v6" ]; then
        echo "ip -6 rule del iif $LAN_IFACE lookup $tbl priority $prio 2>/dev/null || true"
        for s in $v6; do
            echo "ip -6 route del $s dev %i 2>/dev/null || true"
        done
        echo "ip -6 route flush table $tbl 2>/dev/null || true"
    fi
    echo "ip rule del iif $LAN_IFACE lookup $tbl priority $prio 2>/dev/null || true"
    for s in $v4; do
        echo "ip route del $s dev %i 2>/dev/null || true"
    done
    echo "ip route flush table $tbl 2>/dev/null || true"
}

# Inject PostUp/PostDown lines (and Table = off when Pi-bypass is on) into the
# user's wg0.conf. Always strips any prior PostUp / PostDown / Table lines we
# may have written in a previous run, so re-runs converge on the chosen mode.
do_configure_wg_firewall_rules() {
    if ! grep -q '\[Interface\]' "$WG_CONF_DEST"; then
        echo "ERROR: No [Interface] section found in $WG_CONF_DEST" >> "$LOG_FILE"
        return 1
    fi

    # Always strip previously-injected lines first (idempotent re-run).
    sed -i '/^PostUp = /d' "$WG_CONF_DEST"
    sed -i '/^PostDown = /d' "$WG_CONF_DEST"
    sed -i '/^Table = /d'   "$WG_CONF_DEST"

    local pi_bypass="false"
    local up_block down_block
    if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
        pi_bypass="true"
        # Pi-bypass manages DNS via PI_DNS_SERVERS (Pi) + HOME_DNS_* (LAN).
        # Strip DNS= so wg-quick/resolvconf cannot overwrite the Pi's WAN DNS
        # when the tunnel comes up (that would make Pi DNS depend on wg0).
        if grep -qE '^[[:space:]]*DNS[[:space:]]*=' "$WG_CONF_DEST"; then
            echo "[wg] Stripping DNS= from $WG_CONF_DEST (Pi-bypass: Pi DNS is PI_DNS_SERVERS via WAN)" >> "$LOG_FILE"
            sed -i '/^[[:space:]]*DNS[[:space:]]*=/d' "$WG_CONF_DEST"
        fi
        # Split AllowedIPs home subnets into IPv4 / IPv6 buckets.
        local home_v4="" home_v6=""
        while IFS= read -r cidr; do
            [ -z "$cidr" ] && continue
            if [ "$(cidr_family "$cidr")" = "6" ]; then
                home_v6="${home_v6}${home_v6:+ }$cidr"
            else
                home_v4="${home_v4}${home_v4:+ }$cidr"
            fi
        done < <(extract_home_subnets "$WG_CONF_DEST")

        echo "[wg] Pi-bypass routing enabled (table=$WG_BYPASS_TABLE_ID prio=$WG_BYPASS_RULE_PRIO v4='$home_v4' v6='$home_v6')" >> "$LOG_FILE"

        up_block=$( { _wg_pi_bypass_up_cmds   "$home_v4" "$home_v6"; _wg_iptables_up_cmds;   } )
        down_block=$( { _wg_iptables_down_cmds; _wg_pi_bypass_down_cmds "$home_v4" "$home_v6"; } )
    else
        echo "[wg] Pi-bypass routing disabled (legacy mode); wg-quick manages routes" >> "$LOG_FILE"
        up_block=$(_wg_iptables_up_cmds)
        down_block=$(_wg_iptables_down_cmds)
    fi

    # Prefix each non-empty command line with "PostUp = " / "PostDown = ".
    local up_lines down_lines
    up_lines=$(printf '%s\n'   "$up_block"   | sed -e '/^[[:space:]]*$/d' -e 's|^|PostUp = |')
    down_lines=$(printf '%s\n' "$down_block" | sed -e '/^[[:space:]]*$/d' -e 's|^|PostDown = |')

    # Rewrite wg0.conf: copy lines through, and right after the [Interface]
    # header insert (a) Table = off when Pi-bypass is on, (b) all PostUp lines,
    # (c) all PostDown lines. Done in plain bash to avoid awk's -v newline limit.
    local tmp_file="${WG_CONF_DEST}.tmp" inserted="false"
    {
        while IFS= read -r line || [ -n "$line" ]; do
            printf '%s\n' "$line"
            if [ "$inserted" = "false" ] && [[ "$line" =~ ^\[Interface\][[:space:]]*$ ]]; then
                if [ "$pi_bypass" = "true" ]; then
                    printf 'Table = off\n'
                fi
                printf '%s\n' "$up_lines"
                printf '%s\n' "$down_lines"
                inserted="true"
            fi
        done < "$WG_CONF_DEST"
    } > "$tmp_file" && mv "$tmp_file" "$WG_CONF_DEST"
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
    # Always drawn via ui_* so it stays on the operator TTY after detach
    # (stdout is the log file in the unattended phase).
    local box_w=76
    local content_w=72
    local border
    border=$(printf '─%.0s' $(seq 1 $((box_w - 2))))
    
    # Move cursor up to redraw if we've drawn before
    if [ "$PROGRESS_BOX_LINES" -gt 0 ]; then
        # Move up and clear each line
        for ((j=0; j<PROGRESS_BOX_LINES; j++)); do
            ui_printf "\033[A\033[2K"
        done
    fi
    
    local lines=0
    
    # Header
    ui_echo "${CYAN}╭${border}╮${NC}"
    ui_echo "${CYAN}│${NC} ${BOLD}${YELLOW}⚡ Setup Progress${NC}$(printf '%*s' $((content_w - 17)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}├${border}┤${NC}"
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
            ui_echo "${CYAN}│${NC} ${color}${icon} ${step}${NC} ${DIM}${extra}${NC}$(printf '%*s' $padding '') ${CYAN}│${NC}"
        else
            ui_echo "${CYAN}│${NC} ${color}${icon} ${step}${NC}$(printf '%*s' $padding '') ${CYAN}│${NC}"
        fi
        lines=$((lines + 1))
    done
    
    # Footer
    ui_echo "${CYAN}╰${border}╯${NC}"
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
    
    # Run the command in background; output goes to the log only so it cannot
    # interleave with the spinner on the operator TTY.
    echo "[$step_name] Executing: $cmd" >> "$LOG_FILE"
    eval "$cmd" >> "$LOG_FILE" 2>&1 &
    local pid=$!
    
    # Animated spinner while waiting (on the progress TTY, not the log)
    local spin_frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local frame=0
    
    # Show spinner below the box
    ui_printf "   "
    while kill -0 $pid 2>/dev/null; do
        ui_printf "\r   ${YELLOW}%s${NC} Running: ${DIM}%s${NC}   " "${spin_frames[$frame]}" "$step_name"
        frame=$(( (frame + 1) % ${#spin_frames[@]} ))
        sleep 0.1
    done
    # Clear the spinner line
    ui_printf "\r\033[K"
    
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

# --- Interactive prompt layout ---
# Pattern for every question:
#   <blank line>
#   QUESTION (bold)     -- what we are asking
#   helper (dim)        -- clarifies THIS question only
#   ...
#   <blank line>
#   cue: █              -- short input only ([Y/n], path, IP, ...)
#
# Never put helper text before the question (ambiguous vs the previous answer)
# or after the input cue (unread before typing). Set PROMPT_FD=2 when the
# caller captures stdout (command substitution).
PROMPT_FD=1

prompt_q() {
    echo "" >&"$PROMPT_FD"
    echo -e "   ${BOLD}$1${NC}" >&"$PROMPT_FD"
}

prompt_h() {
    echo -e "   ${DIM}$1${NC}" >&"$PROMPT_FD"
}

prompt_hw() {
    echo -e "   ${YELLOW}$1${NC}" >&"$PROMPT_FD"
}

# Print a short input cue and read into PROMPT_REPLY from the TTY.
# $1 = cue text without a trailing colon, e.g. "[Y/n]" or "IP".
prompt_cue() {
    local cue="$1"
    echo "" >&"$PROMPT_FD"
    echo -ne "   ${cue}: " >&"$PROMPT_FD"
    read -r PROMPT_REPLY < /dev/tty
}

# Like prompt_cue, but shows a highlighted default in the cue.
# $1 = label (e.g. "LAN subnet"), $2 = default value (may be empty).
prompt_cue_default() {
    local label="$1" def="$2"
    echo "" >&"$PROMPT_FD"
    if [ -n "$def" ]; then
        echo -ne "   ${label} [default: ${BOLD}${YELLOW}${def}${NC}]: " >&"$PROMPT_FD"
    else
        echo -ne "   ${label}: " >&"$PROMPT_FD"
    fi
    read -r PROMPT_REPLY < /dev/tty
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
# Ask the operator whether to enable Pi-bypass routing (forwarded LAN traffic
# uses wg0; the Pi's own outbound stays on WAN). Persists PI_BYPASS_ROUTING.
#
# This is the recommended mode and the only one that keeps remote management
# (SSH-over-Internet, Pi Connect, apt updates) working when the user's
# wg0.conf has AllowedIPs = 0.0.0.0/0. We only enable it after explicit
# consent because doing so rewrites /etc/wireguard/wg0.conf to set
# `Table = off` and adds policy-routing PostUp/PostDown lines.
prompt_pi_bypass_routing() {
    local has_default_route=""
    if [ -n "${WG_CONF_SRC:-}" ]; then
        has_default_route=$(detect_wg_default_route "$WG_CONF_SRC" 2>/dev/null || true)
    fi

    # Default behaviour:
    #   - Saved value present  -> keep it (interactive AND non-interactive).
    #   - Interactive + no value -> default Y (recommended), but always ask.
    #   - Non-interactive + no value (--yes on a legacy install) -> default
    #     OFF. We do not rewrite an existing wg0.conf without explicit consent.
    local default
    if [ -n "${PI_BYPASS_ROUTING:-}" ]; then
        default="$PI_BYPASS_ROUTING"
    elif [ "$NONINTERACTIVE" = "true" ]; then
        default="false"
    else
        default="true"
    fi

    if [ "$NONINTERACTIVE" = "true" ]; then
        if [ -n "${PI_BYPASS_ROUTING:-}" ]; then
            info "Non-interactive: Pi-bypass routing = $default (from saved config)."
        else
            warn "Non-interactive on a legacy install: Pi-bypass routing left OFF."
            warn "Re-run setup interactively to enable it (recommended)."
        fi
        PI_BYPASS_ROUTING="$default"
        save_config_var "PI_BYPASS_ROUTING" "$PI_BYPASS_ROUTING"
        return
    fi

    local cue
    if [ "$default" = "true" ]; then
        cue="[Y/n]"
    else
        cue="[y/N]"
    fi

    prompt_q "🛡️  Enable Pi-bypass routing? (recommended)"
    prompt_h "LAN clients go through the VPN tunnel; the Pi's own traffic stays on WAN."
    prompt_h "  LAN clients  → wg0 (full-tunnel; kill-switch when wg0 is down)"
    prompt_h "  Pi itself    → WAN (apt, Pi Connect, NTP, DNS, WG handshake)"
    prompt_h "Enabling rewrites wg0.conf (Table=off + policy-routing PostUp/PostDown)."
    if [ -n "$has_default_route" ]; then
        prompt_hw "Your wg0.conf has $has_default_route in AllowedIPs."
        prompt_hw "Without Pi-bypass, starting wg0 sends ALL Pi traffic into the tunnel."
        prompt_hw "If the home peer does not NAT the Pi, you lose Pi Connect / apt / public SSH."
    fi
    prompt_cue "$cue"

    local enabled="$default"
    if [ "$default" = "true" ]; then
        [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]] && enabled="false"
    else
        [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] && enabled="true"
    fi

    PI_BYPASS_ROUTING="$enabled"
    save_config_var "PI_BYPASS_ROUTING" "$PI_BYPASS_ROUTING"

    if [ "$enabled" = "true" ]; then
        success "Pi-bypass routing will be enabled."
    else
        warn "Pi-bypass routing DISABLED. wg0.conf will not be modified for routing."
        if [ -n "$has_default_route" ]; then
            warn "Default-route AllowedIPs will hijack the Pi's outbound traffic when wg0 comes up."
        fi
    fi
}


# Default upstream DNS servers used in tunnel-exit mode. Each is sent out
# via wg0 (using dnsmasq's `server=IP@wg0` source-interface binding), so
# the home peer NATs the lookup from its public IP - DNS responses are
# anchored at the home network's geographic location even though the Pi
# sits abroad.
HOME_DNS_TUNNEL_DEFAULTS="1.1.1.1 8.8.8.8"

# Backward-compat: in the previous release we only had HOME_DNS_SERVERS
# (no HOME_DNS_MODE). Translate a saved-only HOME_DNS_SERVERS value into
# the new MODE/SERVERS pair so legacy configs keep working without an
# interactive re-run.
infer_home_dns_mode_legacy() {
    [ -n "${HOME_DNS_MODE+x}" ] && return 0
    if [ -n "${HOME_DNS_SERVERS+x}" ]; then
        if [ -n "${HOME_DNS_SERVERS:-}" ]; then
            HOME_DNS_MODE="custom"
        else
            HOME_DNS_MODE="skip"
        fi
        save_config_var "HOME_DNS_MODE" "$HOME_DNS_MODE"
    fi
}

# Ask how LAN client DNS lookups should be forwarded.
# Persists HOME_DNS_MODE (tunnel|custom|skip) and HOME_DNS_SERVERS (only
# meaningful when MODE=custom).
#
# Default priority when the operator opts into tunnel-forwarded DNS:
#   1. WireGuard DNS= from the source config  -> MODE=custom (explicit intent)
#   2. Else if AllowedIPs has a default route -> MODE=tunnel (public DNS @wg0)
#   3. Else .1 of first home subnet           -> MODE=custom
#   4. Else ask for an IP                     -> MODE=custom
#
# WireGuard DNS= is client-mode host resolv.conf semantics; under Pi-bypass
# it is NOT applied to the Pi. We reuse the values for LAN dnsmasq only.
# Interactive layout: question → dim helper → short input cue (see prompt_q).

prompt_home_dns() {
    if [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
        HOME_DNS_MODE="${HOME_DNS_MODE:-skip}"
        HOME_DNS_SERVERS="${HOME_DNS_SERVERS:-}"
        save_config_var "HOME_DNS_MODE" "$HOME_DNS_MODE"
        save_config_var "HOME_DNS_SERVERS" "$HOME_DNS_SERVERS"
        return
    fi

    local has_default_route="" home_subnets="" suggested_home_ip="" wg_dns=""
    if [ -n "${WG_CONF_SRC:-}" ]; then
        has_default_route=$(detect_wg_default_route "$WG_CONF_SRC" 2>/dev/null || true)
        suggested_home_ip=$(suggest_home_dns_default "$WG_CONF_SRC" 2>/dev/null || true)
        home_subnets=$(extract_home_subnets "$WG_CONF_SRC" 2>/dev/null)
        wg_dns=$(extract_wg_dns_servers "$WG_CONF_SRC" 2>/dev/null || true)
    fi

    local tunnel_available="false"
    [ -n "$has_default_route" ] && tunnel_available="true"

    _home_dns_accept_custom() {
        local normalized="$1"
        local entry covered any_uncovered=false
        local has_v4_default=false has_v6_default=false
        case "$has_default_route" in
            *'0.0.0.0/0'*|*'split-default-route'*) has_v4_default=true ;;
        esac
        case "$has_default_route" in
            *'::/0'*) has_v6_default=true ;;
        esac
        for entry in $normalized; do
            covered=false
            if [[ "$entry" == *:* ]]; then
                [ "$has_v6_default" = true ] && covered=true
            else
                [ "$has_v4_default" = true ] && covered=true
            fi
            if [ "$covered" != true ]; then
                local cidr
                for cidr in $home_subnets; do
                    if [[ "$entry" == *:* ]]; then
                        [ "$(cidr_family "$cidr")" = "6" ] || continue
                        covered=true
                        break
                    else
                        if ipv4_in_cidr "$entry" "$cidr"; then covered=true; break; fi
                    fi
                done
            fi
            if [ "$covered" != true ]; then
                warn "  $entry is NOT covered by any AllowedIPs CIDR in wg0.conf."
                warn "  WireGuard will drop packets to it unless you add it to AllowedIPs."
                any_uncovered=true
            fi
        done
        if [ "$any_uncovered" = true ]; then
            if [ "$NONINTERACTIVE" = "true" ]; then
                warn "Non-interactive: accepting uncovered DNS servers anyway."
            else
                prompt_q "Use these DNS servers anyway?"
                prompt_hw "One or more addresses are outside AllowedIPs — WireGuard may drop them."
                prompt_cue "[y/N]"
                [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] || return 1
            fi
        fi
        HOME_DNS_MODE="custom"
        HOME_DNS_SERVERS="$normalized"
        success "LAN DNS upstream: $HOME_DNS_SERVERS (via tunnel)"
        return 0
    }

    _home_dns_set_tunnel() {
        HOME_DNS_MODE="tunnel"
        HOME_DNS_SERVERS=""
        success "LAN DNS upstream: ${HOME_DNS_TUNNEL_DEFAULTS} via wg0 (tunnel-exit)"
    }

    local default_yes="true"
    [ "${HOME_DNS_MODE:-}" = "skip" ] && default_yes="false"

    local forward_choice="$default_yes"
    if [ "$NONINTERACTIVE" = "true" ]; then
        if [ -n "${HOME_DNS_MODE+x}" ]; then
            [ "${HOME_DNS_MODE}" != "skip" ] && forward_choice="true" || forward_choice="false"
            info "Non-interactive: HOME_DNS_MODE = ${HOME_DNS_MODE} (from saved config)."
        else
            forward_choice="true"
            info "Non-interactive default: forwarding LAN DNS through tunnel."
        fi
    else
        local cue1="[Y/n]"
        [ "$default_yes" = "false" ] && cue1="[y/N]"
        prompt_q "📡 Forward LAN DNS through the VPN tunnel?"
        prompt_h "Devices on the Pi LAN get DNS from this Pi (dnsmasq)."
        prompt_h "Forwarding through the tunnel makes answers match your home location (GeoDNS)."
        prompt_cue "$cue1"
        if [ "$default_yes" = "true" ]; then
            [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]] && forward_choice="false"
        else
            [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] && forward_choice="true"
        fi
    fi

    if [ "$forward_choice" = "false" ]; then
        HOME_DNS_MODE="skip"
        HOME_DNS_SERVERS=""
        warn "LAN DNS will use the Pi's WAN ISP DNS (geo-leaks to WAN location)."
        save_config_var "HOME_DNS_MODE" "$HOME_DNS_MODE"
        save_config_var "HOME_DNS_SERVERS" "$HOME_DNS_SERVERS"
        return
    fi

    if [ "$NONINTERACTIVE" = "true" ]; then
        if [ "${HOME_DNS_MODE:-}" = "custom" ] && [ -n "${HOME_DNS_SERVERS:-}" ]; then
            info "Non-interactive: HOME_DNS_SERVERS = '$HOME_DNS_SERVERS' (from saved config)."
        elif [ "${HOME_DNS_MODE:-}" = "tunnel" ]; then
            _home_dns_set_tunnel
        elif [ -n "$wg_dns" ]; then
            _home_dns_accept_custom "$wg_dns" || true
            [ "$HOME_DNS_MODE" = "custom" ] || _home_dns_set_tunnel
            info "Non-interactive: using WireGuard DNS= ($HOME_DNS_SERVERS)."
        elif [ "$tunnel_available" = "true" ]; then
            _home_dns_set_tunnel
            info "Non-interactive: tunnel-exit mode."
        elif [ -n "$suggested_home_ip" ]; then
            _home_dns_accept_custom "$suggested_home_ip" || true
            info "Non-interactive: custom home DNS = ${HOME_DNS_SERVERS:-$suggested_home_ip}"
        else
            HOME_DNS_MODE="skip"
            HOME_DNS_SERVERS=""
            warn "Non-interactive: no DNS= / default-route / home subnet to suggest."
            warn "Falling back to skip mode (LAN DNS leaks to WAN)."
        fi
        save_config_var "HOME_DNS_MODE" "$HOME_DNS_MODE"
        save_config_var "HOME_DNS_SERVERS" "$HOME_DNS_SERVERS"
        return
    fi

    if [ -n "$wg_dns" ]; then
        prompt_q "📡 Use these DNS servers for LAN clients?"
        prompt_h "Found in your WireGuard config:"
        echo -e "   ${BOLD}DNS = $wg_dns${NC}"
        prompt_h "LAN clients would use these via the tunnel (local hostnames, Pi-hole, etc.)."
        prompt_h "The Pi itself still uses PI_DNS_SERVERS over WAN — not this list."
        prompt_cue "[Y/n]"
        if [[ ! "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
            if _home_dns_accept_custom "$wg_dns"; then
                save_config_var "HOME_DNS_MODE" "$HOME_DNS_MODE"
                save_config_var "HOME_DNS_SERVERS" "$HOME_DNS_SERVERS"
                return
            fi
        fi

        prompt_q "📡 Override LAN DNS upstream"
        if [ "$tunnel_available" = "true" ]; then
            prompt_h "Press Enter / type 'tunnel' → public DNS ${HOME_DNS_TUNNEL_DEFAULTS} via wg0"
        fi
        prompt_h "Type other DNS IP(s) → custom upstream via the tunnel"
        prompt_h "Type 'skip' → use Pi WAN DNS (geo-leaks)"
        if [ "$tunnel_available" = "true" ]; then
            prompt_cue_default "Upstream" "tunnel-exit"
        else
            prompt_cue "IP(s) or 'skip'"
        fi

        while true; do
            local raw="$PROMPT_REPLY"
            if [ -z "$raw" ] || [ "$raw" = "tunnel" ] || [ "$raw" = "tunnel-exit" ]; then
                if [ "$tunnel_available" = "true" ]; then
                    _home_dns_set_tunnel
                    break
                fi
                warn "Tunnel-exit needs AllowedIPs 0.0.0.0/0 (or ::/0). Enter IP(s) instead."
                prompt_cue "IP(s) or 'skip'"
                continue
            fi
            if [ "$raw" = "skip" ]; then
                HOME_DNS_MODE="skip"
                HOME_DNS_SERVERS=""
                warn "LAN DNS will use the Pi's WAN ISP DNS (geo-leaks)."
                break
            fi
            if [ "$raw" = "wg" ] || [ "$raw" = "DNS" ] || [ "$raw" = "dns" ]; then
                raw="$wg_dns"
            fi
            local normalized
            normalized=$(normalize_ip_list "$raw")
            if [ -z "$normalized" ]; then
                warn "No valid IPv4/IPv6 addresses parsed from '$raw'. Try again."
                prompt_cue "IP(s) or 'skip'"
                continue
            fi
            _home_dns_accept_custom "$normalized" || { prompt_cue "IP(s) or 'skip'"; continue; }
            break
        done

        save_config_var "HOME_DNS_MODE" "$HOME_DNS_MODE"
        save_config_var "HOME_DNS_SERVERS" "$HOME_DNS_SERVERS"
        return
    fi

    if [ "$tunnel_available" = "true" ]; then
        prompt_q "📡 LAN DNS upstream"
        prompt_h "No DNS= in your WireGuard config. Default is tunnel-exit:"
        prompt_h "dnsmasq → ${HOME_DNS_TUNNEL_DEFAULTS} via wg0 (home peer NATs the lookup)."
        prompt_h "Override: type a home DNS IP (e.g. Pi-hole), or 'skip'."
        if [ -n "$suggested_home_ip" ]; then
            prompt_h "Suggestion if you have a home resolver: ${suggested_home_ip}"
        fi
        prompt_cue_default "Upstream" "tunnel-exit"
    elif [ -n "$suggested_home_ip" ]; then
        prompt_q "📡 LAN DNS upstream"
        prompt_h "Default: ${suggested_home_ip} (.1 of first home AllowedIPs subnet)."
        prompt_hw "Tunnel-exit unavailable (no 0.0.0.0/0 in AllowedIPs)."
        prompt_cue_default "Upstream" "$suggested_home_ip"
    else
        prompt_q "📡 LAN DNS upstream"
        prompt_h "Type one or more home-network DNS server IPs (space/comma separated)."
        prompt_hw "Tunnel-exit unavailable (no 0.0.0.0/0 in AllowedIPs)."
        prompt_cue "IP(s) or 'skip'"
    fi

    while true; do
        local raw="$PROMPT_REPLY"
        if [ -z "$raw" ] || [ "$raw" = "tunnel" ] || [ "$raw" = "tunnel-exit" ]; then
            if [ "$tunnel_available" = "true" ]; then
                _home_dns_set_tunnel
                break
            elif [ -z "$raw" ] && [ -n "$suggested_home_ip" ]; then
                raw="$suggested_home_ip"
            elif [ -z "$raw" ]; then
                warn "No DNS server entered. Try again, or type 'skip'."
                prompt_cue "IP(s) or 'skip'"
                continue
            else
                warn "Tunnel-exit needs AllowedIPs 0.0.0.0/0 (or ::/0)."
                prompt_cue "IP(s) or 'skip'"
                continue
            fi
        fi

        if [ "$raw" = "skip" ]; then
            HOME_DNS_MODE="skip"
            HOME_DNS_SERVERS=""
            warn "LAN DNS will use the Pi's WAN ISP DNS (geo-leaks)."
            break
        fi

        local normalized
        normalized=$(normalize_ip_list "$raw")
        if [ -z "$normalized" ]; then
            warn "No valid IPv4/IPv6 addresses parsed from '$raw'. Try again."
            prompt_cue "IP(s) or 'skip'"
            continue
        fi
        _home_dns_accept_custom "$normalized" || { prompt_cue "IP(s) or 'skip'"; continue; }
        break
    done

    save_config_var "HOME_DNS_MODE" "$HOME_DNS_MODE"
    save_config_var "HOME_DNS_SERVERS" "$HOME_DNS_SERVERS"
}

prompt_pi_dns() {
    if [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
        PI_DNS_SERVERS="${PI_DNS_SERVERS:-}"
        save_config_var "PI_DNS_SERVERS" "$PI_DNS_SERVERS"
        return
    fi

    local default="${PI_DNS_SERVERS:-1.1.1.1 8.8.8.8}"

    if [ "$NONINTERACTIVE" = "true" ]; then
        PI_DNS_SERVERS="$(normalize_ip_list "$default")"
        info "Non-interactive: PI_DNS_SERVERS = '$PI_DNS_SERVERS'"
        save_config_var "PI_DNS_SERVERS" "$PI_DNS_SERVERS"
        return
    fi

    while true; do
        prompt_q "🌐 DNS for the Pi itself (always via WAN)"
        prompt_h "Used by apt, NTP, Pi Connect, and the WireGuard endpoint hostname."
        prompt_h "Must work even when the tunnel is down. Public resolvers are recommended."
        prompt_cue_default "DNS servers" "$default"
        local raw="$PROMPT_REPLY"
        [ -z "$raw" ] && raw="$default"
        local normalized
        normalized=$(normalize_ip_list "$raw")
        if [ -z "$normalized" ]; then
            warn "No valid IPv4/IPv6 addresses parsed from '$raw'. Try again."
            continue
        fi
        PI_DNS_SERVERS="$normalized"
        success "Pi-local DNS: $PI_DNS_SERVERS"
        break
    done

    save_config_var "PI_DNS_SERVERS" "$PI_DNS_SERVERS"
}

prompt_wan_static_ip() {
    detect_wan_network "$WAN_IFACE"

    local already_static=false
    if wan_has_static_ip "$WAN_IFACE"; then
        already_static=true
    fi

    local default_yes=true
    [ "$already_static" = true ] && default_yes=false
    local cue="[Y/n]"
    [ "$default_yes" = true ] || cue="[y/N]"

    if [ "$already_static" = true ]; then
        prompt_q "🔒 Reconfigure static IP on $WAN_IFACE?"
    else
        prompt_q "🔒 Configure a static IP on $WAN_IFACE? (recommended)"
    fi
    prompt_h "A static WAN IP keeps the Pi reachable at a predictable address"
    prompt_h "(SSH, diagnostics, port forwards) on the upstream network."
    if [ -n "$WAN_CURRENT_IP" ]; then
        prompt_h "Current IP on $WAN_IFACE: ${WAN_CURRENT_IP}/${WAN_CURRENT_PREFIX}"
    fi
    if [ -n "$WAN_GATEWAY" ]; then
        prompt_h "Detected gateway: ${WAN_GATEWAY}"
    fi
    if [ "$already_static" = true ]; then
        echo -e "   ${GREEN}✔ $WAN_IFACE already appears to have a static configuration.${NC}"
    fi
    prompt_cue "$cue"

    local enabled="false"
    if [ "$default_yes" = true ]; then
        [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]] || enabled="true"
    else
        [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] && enabled="true"
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
        prompt_q "📌 WAN static IP address"
        prompt_h "IPv4 address to assign to $WAN_IFACE."
        prompt_cue_default "IP" "$default_ip"
        local user_ip="$PROMPT_REPLY"
        [ -z "$user_ip" ] && user_ip="$default_ip"
        if is_valid_ipv4 "$user_ip"; then
            WAN_STATIC_IP="$user_ip"
            break
        fi
        warn "Not a valid IPv4 address: $user_ip"
    done

    local default_prefix="${WAN_STATIC_PREFIX:-${WAN_CURRENT_PREFIX:-24}}"
    while true; do
        prompt_q "📐 WAN prefix length"
        prompt_h "CIDR prefix for the static address (usually 24)."
        prompt_cue_default "Prefix" "$default_prefix"
        local user_prefix="$PROMPT_REPLY"
        [ -z "$user_prefix" ] && user_prefix="$default_prefix"
        if echo "$user_prefix" | grep -Eq '^[0-9]+$' && [ "$user_prefix" -ge 8 ] && [ "$user_prefix" -le 32 ]; then
            WAN_STATIC_PREFIX="$user_prefix"
            break
        fi
        warn "Prefix must be an integer between 8 and 32."
    done

    local default_gateway="${WAN_STATIC_GATEWAY:-${WAN_GATEWAY}}"
    while true; do
        prompt_q "🧭 WAN gateway"
        prompt_h "Upstream default gateway for $WAN_IFACE (leave empty only if none)."
        prompt_cue_default "Gateway" "$default_gateway"
        local user_gateway="$PROMPT_REPLY"
        [ -z "$user_gateway" ] && user_gateway="$default_gateway"
        if [ -z "$user_gateway" ] || is_valid_ipv4 "$user_gateway"; then
            WAN_STATIC_GATEWAY="$user_gateway"
            break
        fi
        warn "Not a valid IPv4 address: $user_gateway"
    done

    local default_dns="${WAN_STATIC_DNS:-1.1.1.1 8.8.8.8}"
    prompt_q "🌐 WAN DNS servers"
    prompt_h "Used while the static WAN config is applied (space-separated)."
    prompt_cue_default "DNS servers" "$default_dns"
    local user_dns="$PROMPT_REPLY"
    [ -z "$user_dns" ] && user_dns="$default_dns"
    WAN_STATIC_DNS="$user_dns"

    save_config_var "WAN_STATIC_IP" "$WAN_STATIC_IP"
    save_config_var "WAN_STATIC_PREFIX" "$WAN_STATIC_PREFIX"
    save_config_var "WAN_STATIC_GATEWAY" "$WAN_STATIC_GATEWAY"
    save_config_var "WAN_STATIC_DNS" "$WAN_STATIC_DNS"
    success "WAN static: $WAN_STATIC_IP/$WAN_STATIC_PREFIX via ${WAN_STATIC_GATEWAY:-<none>} DNS=$WAN_STATIC_DNS"
}

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

    # Wireless NICs expose /sys/class/net/<iface>/wireless or phy80211.
    # Detect this first so we can label them as Wi-Fi regardless of bus.
    if [ -d "/sys/class/net/$iface/wireless" ] || [ -L "/sys/class/net/$iface/phy80211" ]; then
        bus_type="wifi"
    elif [ -L "/sys/class/net/$iface/device" ]; then
        # Resolve to the absolute device path so the parent USB controller is
        # visible. `readlink` (without -f) only returns the relative target
        # which on a Pi 4 is something like ../../../1-1.3:1.0 and does NOT
        # contain the substring "usb", causing USB NICs to be mis-detected
        # as onboard. Use `readlink -f` to get the real path under /sys/devices.
        devpath=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)
        case "$devpath" in
            *"/usb"*) bus_type="usb" ;;
            *"/pci"*) bus_type="pci" ;;
            *)        bus_type="onboard" ;;
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
        local details detail_line1 detail_line2 bus badge
        details=$(get_interface_details "$iface")
        detail_line1=$(echo "$details" | sed -n '1p')
        detail_line2=$(echo "$details" | sed -n '2p')
        bus=$(echo "$detail_line2" | sed -n 's/.*bus=\([^ ]*\).*/\1/p')

        # Render a prominent badge so the operator can tell at a glance
        # which interface is the Pi's built-in port versus a USB adapter
        # or wireless radio. The built-in port is the most common LAN
        # candidate on a Pi 4 (USB ports are typically used for the WAN
        # uplink), so we highlight it distinctly.
        case "$bus" in
            onboard|pci) badge="${GREEN}${BOLD}[ Pi built-in ]${NC}" ;;
            usb)         badge="${YELLOW}${BOLD}[ USB adapter ]${NC}" ;;
            wifi)        badge="${MAGENTA}${BOLD}[ Wi-Fi ]${NC}" ;;
            virtual)     badge="${DIM}[ virtual ]${NC}" ;;
            *)           badge="${DIM}[ ${bus:-unknown} ]${NC}" ;;
        esac

        printf "   %2d) ${BOLD}%-7s${NC} %b\n" "$idx" "$iface" "$badge" >&2
        printf "       ${DIM}%s${NC}\n" "$detail_line1" >&2
        printf "       ${DIM}%s${NC}\n" "$detail_line2" >&2
        iface_list+=("$iface")
        idx=$((idx + 1))
    done
    echo "" >&2

    local old_fd="$PROMPT_FD"
    PROMPT_FD=2
    prompt_q "👉 Select interface number"
    if [ -n "$default_iface" ]; then
        prompt_h "Press Enter for the default, or type a number from the list above."
        prompt_cue_default "Number" "$default_iface"
    else
        prompt_h "Type a number from the list above."
        prompt_cue "Number"
    fi
    PROMPT_FD="$old_fd"

    while true; do
        local choice="$PROMPT_REPLY"
        # If the default iface name was accepted via empty Enter, map it.
        if [ -z "$choice" ] && [ -n "$default_iface" ]; then
            chosen_iface="$default_iface"
            break
        fi
        # Allow typing the interface name as well as the number / default name.
        if [ -n "$default_iface" ] && [ "$choice" = "$default_iface" ]; then
            chosen_iface="$default_iface"
            break
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#iface_list[@]}" ]; then
            chosen_iface="${iface_list[$((choice-1))]}"
            break
        fi
        if [ -n "$default_iface" ]; then
            warn "Invalid selection. Press Enter for default or choose a valid number." >&2
        else
            warn "Invalid selection. Please try again." >&2
        fi
        PROMPT_FD=2
        if [ -n "$default_iface" ]; then
            prompt_cue_default "Number" "$default_iface"
        else
            prompt_cue "Number"
        fi
        PROMPT_FD="$old_fd"
    done

    echo "$chosen_iface"
}

get_wg_config() {
    # Pre-fill default from config if available
    local default_path="${WG_CONF_PATH:-}"
    local old_fd="$PROMPT_FD"
    PROMPT_FD=2

    while true; do
        # Prompt to stderr so it is visible when stdout is captured by command substitution.
        prompt_q "📂 WireGuard peer config file"
        prompt_h "Contains your private key and peer settings for the home VPN."
        echo "" >&2
        if [ -n "$default_path" ]; then
            echo -ne "   Path [default: ${BOLD}${YELLOW}${default_path}${NC}]: " >&2
            read -e -i "$default_path" -r input_path < /dev/tty
        else
            echo -ne "   Path: " >&2
            read -e -r input_path < /dev/tty
        fi

        if [ -z "$input_path" ] && [ -n "$default_path" ]; then
            wg_conf_path="$default_path"
        else
            wg_conf_path="$input_path"
        fi

        if [ -f "$wg_conf_path" ]; then
            echo "$wg_conf_path"
            WG_CONF_PATH="$wg_conf_path"
            PROMPT_FD="$old_fd"
            break
        else
            warn "File not found: $wg_conf_path. Please try again." >&2
        fi
    done
    PROMPT_FD="$old_fd"
}

get_ip_range() {
    local default_cidr="${LAN_CIDR:-10.10.10.0/24}"
    local old_fd="$PROMPT_FD"
    PROMPT_FD=2

    echo "[DEBUG] Entering get_ip_range function" >> "$LOG_FILE"

    prompt_q "🌐 LAN IP range (CIDR)"
    prompt_h "Private subnet for devices on the LAN/AP side."
    prompt_h "Subnets are locked to /24 (other prefixes are coerced)."
    prompt_cue_default "CIDR" "$default_cidr"
    local input_cidr="$PROMPT_REPLY"

    echo "[DEBUG] Read IP input: '$input_cidr'" >> "$LOG_FILE"

    if [ -z "$input_cidr" ]; then
        LAN_CIDR="$default_cidr"
    else
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

    PROMPT_FD="$old_fd"
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

# Collect any user confirmations needed because of remote-management
# disconnect risk during install. MUST be called during the input-collection
# phase only - never during execution - so the run can proceed unattended
# once started.
#
# Detected risks:
#   - SSH session on LAN interface that will be reconfigured.
#   - SSH session on WAN interface that will get a new static IP.
#   - Pi Connect / similar daemon active and a step that will route the
#     Pi's outbound traffic through wg0 (AllowedIPs default-route).
#   - Generic Pi Connect detection without WireGuard default-route -
#     informational only; the script will still self-detach so a Pi Connect
#     drop cannot leave setup half-done.
prompt_ssh_safety_warnings() {
    SSH_DISCONNECT_ACK="false"
    SSH_IFACE="$(detect_ssh_iface)"

    local pi_connect_active wg_default_route
    pi_connect_active=$(detect_pi_connect_active 2>/dev/null || true)
    wg_default_route=""
    if [ -n "${WG_CONF_SRC:-}" ]; then
        wg_default_route=$(detect_wg_default_route "$WG_CONF_SRC" 2>/dev/null || true)
    fi

    local wan_static_planned="${WAN_STATIC_IP_ENABLED:-false}"
    local lan_will_change=true
    if lan_iface_has_gateway_ip; then
        lan_will_change=false
    fi

    local risk=false risk_lines=()

    if [ -n "$SSH_IFACE" ]; then
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
    fi

    if [ -n "$wg_default_route" ] && [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
        risk=true
        risk_lines+=("• WireGuard config has $wg_default_route in AllowedIPs.")
        risk_lines+=("  Starting wg0 will route ALL the Pi's outbound traffic through the tunnel.")
        if [ -n "$pi_connect_active" ]; then
            risk_lines+=("  Raspberry Pi Connect is active - its WebRTC session WILL be dropped")
            risk_lines+=("  unless your WireGuard peer NATs the Pi's traffic out to the Internet.")
        else
            risk_lines+=("  Any remote-management session that depends on outbound Internet (SSH over")
            risk_lines+=("  the public IP, Pi Connect, ngrok, etc.) WILL be dropped unless your peer")
            risk_lines+=("  NATs the Pi's traffic out to the Internet.")
        fi
        risk_lines+=("  Tip: enable Pi-bypass routing on the previous prompt to eliminate this risk.")
        if [ -z "$SSH_IFACE" ] && [ -z "$pi_connect_active" ]; then
            risk_lines+=("  (You appear to be on a local console - no immediate action needed.)")
        fi
    elif [ -n "$wg_default_route" ] && [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
        # Default-route AllowedIPs is fine when Pi-bypass routing keeps the
        # Pi's own traffic on WAN. Surface it as informational, not a risk.
        echo ""
        info "WireGuard config has $wg_default_route in AllowedIPs, but Pi-bypass"
        info "routing is enabled - the Pi's own traffic stays on WAN. Safe."
    fi

    # Pi Connect on its own - no WG default route, no SSH session - is not a
    # hard risk, but the operator should still know that the script will
    # self-detach so a Pi Connect blip cannot leave setup half-done.
    if [ -z "$SSH_IFACE" ] && [ -n "$pi_connect_active" ] && [ -z "$wg_default_route" ]; then
        echo ""
        info "Detected Raspberry Pi Connect session. Setup will detach from your"
        info "terminal after the input phase so any Connect blip cannot interrupt it."
    fi

    if [ "$risk" = false ]; then
        SSH_DISCONNECT_ACK="true"
        return 0
    fi

    prompt_q "❓ Acknowledge disconnect risk and continue?"
    prompt_hw "Remote-management disconnect risk detected:"
    local line
    for line in "${risk_lines[@]}"; do
        prompt_hw "$line"
    done
    prompt_h "After this, setup switches to unattended mode and keeps running if your session drops."
    prompt_h "You may need to reconnect afterward."
    if [ "$NONINTERACTIVE" = "true" ]; then
        info "Non-interactive: proceeding (the operator must reconnect manually if disconnected)."
        SSH_DISCONNECT_ACK="true"
        return 0
    fi
    prompt_cue "[y/N]"
    if [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]]; then
        SSH_DISCONNECT_ACK="true"
    else
        error "Aborted by user (disconnect risk not acknowledged)."
        exit 1
    fi
}

do_configure_dnsmasq() {
    # Backup original /etc/dnsmasq.conf only the first time so re-runs do not
    # overwrite the genuine original (cleanup relies on this to restore state).
    if [ ! -f /etc/dnsmasq.conf.bak ] && [ -f /etc/dnsmasq.conf ]; then
        cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
    fi

    # Prevent Debian's dnsmasq package from registering 127.0.0.1 with
    # resolvconf. That hijacks the Pi's own resolver and breaks apt / the
    # WireGuard endpoint hostname lookup (exactly the failure mode where
    # wg-quick reports "Temporary failure in name resolution").
    if [ -f /etc/default/dnsmasq ]; then
        if grep -qE '^[[:space:]]*IGNORE_RESOLVCONF=' /etc/default/dnsmasq; then
            sed -i 's/^[[:space:]]*IGNORE_RESOLVCONF=.*/IGNORE_RESOLVCONF=yes/' /etc/default/dnsmasq
        else
            printf '\n# Managed by raspberrypi-site2site-wireguard: keep Pi DNS on WAN\nIGNORE_RESOLVCONF=yes\n' \
                >> /etc/default/dnsmasq
        fi
    fi
    # Drop any leftover lo.dnsmasq record from a previous package-default start.
    if command -v resolvconf >/dev/null 2>&1; then
        resolvconf -d lo.dnsmasq >> "$LOG_FILE" 2>&1 || true
    fi

    local server
    {
        printf '# Managed by raspberrypi-site2site-wireguard setup-vpn-gateway.sh\n'
        printf 'interface=%s\n' "$LAN_IFACE"
        printf 'except-interface=lo\n'
        printf 'except-interface=%s\n' "$WAN_IFACE"
        printf 'bind-dynamic\n'

        # Dual-DNS plane: forward LAN client DNS via wg0 (geo-correct DNS)
        # when the operator has opted into a tunnel-routing mode. dnsmasq's
        # own /etc/resolv.conf is bypassed via 'no-resolv' so the Pi-local
        # public-DNS settings (PI_DNS_SERVERS) do not bleed into LAN clients.
        case "${HOME_DNS_MODE:-skip}" in
            tunnel)
                # Public DNS via wg0: dnsmasq binds the upstream socket to
                # wg0 (`@wg0`), so each query exits via the tunnel; the home
                # peer NATs it out to the Internet from the home location.
                printf 'no-resolv\n'
                for server in $HOME_DNS_TUNNEL_DEFAULTS; do
                    printf 'server=%s@wg0\n' "$server"
                done
                ;;
            custom)
                # Specific home-network DNS server(s) (e.g. Pi-hole). The
                # destination IP is in a home AllowedIPs subnet, so the main
                # routing table sends the lookup via wg0 automatically.
                if [ -n "${HOME_DNS_SERVERS:-}" ]; then
                    printf 'no-resolv\n'
                    for server in $HOME_DNS_SERVERS; do
                        printf 'server=%s\n' "$server"
                    done
                fi
                ;;
            skip|*)
                # No upstream override: dnsmasq reads /etc/resolv.conf, which
                # points at PI_DNS_SERVERS over WAN. LAN client DNS leaks.
                ;;
        esac

        printf 'dhcp-range=%s,%s,255.255.255.0,24h\n' "$DHCP_START" "$DHCP_END"
        printf 'dhcp-option=option:dns-server,%s\n' "$LAN_GATEWAY"
        printf 'dhcp-option=option:router,%s\n' "$LAN_GATEWAY"
    } > /etc/dnsmasq.conf

    systemctl restart dnsmasq
    systemctl enable dnsmasq
}

# Configure the Pi's OWN DNS so that locally-generated lookups (apt, NTP,
# Pi Connect, the WireGuard endpoint hostname, etc.) keep working via WAN
# regardless of tunnel state. Backs up the previous /etc/resolv.conf the
# first time so cleanup can restore it.
#
# Only runs when PI_BYPASS_ROUTING is enabled and PI_DNS_SERVERS is set; in
# legacy mode we leave the system DNS configuration alone (the Pi's traffic
# goes through the tunnel so the home peer's DNS is what gets used anyway).
do_configure_pi_dns() {
    if [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
        echo "[pi_dns] Pi-bypass disabled; leaving Pi DNS configuration alone." >> "$LOG_FILE"
        return 0
    fi
    if [ -z "${PI_DNS_SERVERS:-}" ]; then
        echo "[pi_dns] PI_DNS_SERVERS empty; not touching Pi DNS." >> "$LOG_FILE"
        return 0
    fi

    echo "[pi_dns] Setting Pi-local DNS via WAN: $PI_DNS_SERVERS" >> "$LOG_FILE"

    # Belt-and-suspenders: if dnsmasq was started by its package postinst
    # before we could set IGNORE_RESOLVCONF, drop any lo.dnsmasq hijack now
    # so the rest of setup (and the WG endpoint hostname lookup) can resolve.
    if [ -f /etc/default/dnsmasq ]; then
        if grep -qE '^[[:space:]]*IGNORE_RESOLVCONF=' /etc/default/dnsmasq; then
            sed -i 's/^[[:space:]]*IGNORE_RESOLVCONF=.*/IGNORE_RESOLVCONF=yes/' /etc/default/dnsmasq
        else
            printf '\n# Managed by raspberrypi-site2site-wireguard: keep Pi DNS on WAN\nIGNORE_RESOLVCONF=yes\n' \
                >> /etc/default/dnsmasq
        fi
    fi
    if command -v resolvconf >/dev/null 2>&1; then
        resolvconf -d lo.dnsmasq >> "$LOG_FILE" 2>&1 || true
    fi

    # Back up /etc/resolv.conf the first time so cleanup can restore it. We
    # back up the file (or the symlink target if it is a symlink) verbatim.
    if [ ! -e /etc/resolv.conf.bak_gateway ] && [ -e /etc/resolv.conf ]; then
        cp -a /etc/resolv.conf /etc/resolv.conf.bak_gateway 2>>"$LOG_FILE" || true
    fi

    local applied=false

    # Path 1: NetworkManager owns the WAN connection. Set per-connection DNS
    # and ignore DHCP-supplied DNS so /etc/resolv.conf reflects PI_DNS_SERVERS.
    # We use 'dev reapply' instead of 'con up' to avoid bouncing the link
    # (which would briefly drop SSH if the operator is on WAN).
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; then
        local con_name
        con_name=$(nmcli -t -f NAME,DEVICE connection show 2>/dev/null \
                   | grep ":$WAN_IFACE$" | cut -d: -f1 | head -n1)
        if [ -n "$con_name" ]; then
            local dns_csv="${PI_DNS_SERVERS// /,}"
            nmcli con modify "$con_name" \
                ipv4.ignore-auto-dns yes \
                ipv4.dns "$dns_csv" >> "$LOG_FILE" 2>&1 || true
            # 'dev reapply' avoids dropping the carrier; falls back to a quiet
            # 'con up' only if reapply is unsupported or the connection is not
            # currently active.
            nmcli dev reapply "$WAN_IFACE" >> "$LOG_FILE" 2>&1 \
                || nmcli con up "$con_name" >> "$LOG_FILE" 2>&1 || true
            applied=true
        fi
    fi

    # Path 2: dhcpcd. Inject a managed block scoped to WAN so the DHCP-supplied
    # DNS is overridden but the rest of dhcpcd's behaviour is intact.
    if [ "$applied" = false ] && [ -f /etc/dhcpcd.conf ]; then
        sed -i '/# VPN-GATEWAY-PI-DNS-START/,/# VPN-GATEWAY-PI-DNS-END/d' /etc/dhcpcd.conf
        {
            echo '# VPN-GATEWAY-PI-DNS-START'
            echo "interface $WAN_IFACE"
            echo "static domain_name_servers=$PI_DNS_SERVERS"
            echo '# VPN-GATEWAY-PI-DNS-END'
        } >> /etc/dhcpcd.conf
        systemctl restart dhcpcd >> "$LOG_FILE" 2>&1 || true
        applied=true
    fi

    # Path 3: neither NM nor dhcpcd -> write DNS via resolvconf if present,
    # otherwise write /etc/resolv.conf directly. Installing the resolvconf
    # package (a setup dependency for wg-quick) turns /etc/resolv.conf into
    # a managed file; a raw overwrite would be clobbered on the next update.
    if [ "$applied" = false ]; then
        local server
        if command -v resolvconf >/dev/null 2>&1; then
            {
                for server in $PI_DNS_SERVERS; do
                    echo "nameserver $server"
                done
            } | resolvconf -a "wan.${WAN_IFACE}.vpn-gateway" >> "$LOG_FILE" 2>&1 || true
            # Also pin the values in resolvconf's head file so they survive
            # interface flaps that delete the dynamic wan.* record.
            mkdir -p /etc/resolvconf/resolv.conf.d
            {
                echo "# Managed by raspberrypi-site2site-wireguard"
                for server in $PI_DNS_SERVERS; do
                    echo "nameserver $server"
                done
            } > /etc/resolvconf/resolv.conf.d/head
            resolvconf -u >> "$LOG_FILE" 2>&1 || true
        else
            {
                echo "# Managed by raspberrypi-site2site-wireguard"
                for server in $PI_DNS_SERVERS; do
                    echo "nameserver $server"
                done
            } > /etc/resolv.conf
        fi
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
            prompt_q "Proceed with existing configuration?"
            prompt_h "Reuse saved settings from vpn-gateway.conf (skip re-asking most questions)."
            prompt_cue "[Y/n]"
            if [[ ! "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
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
            prompt_q "📦 Install required system packages?"
            prompt_h "Missing:$MISSING_PKGS"
            prompt_cue "[Y/n]"
            if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
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
        echo ""
        echo -e "   ${BOLD}Network interface selection${NC}"
        prompt_h "Identify which port is WAN (Internet) and which is LAN (private subnet)."
        
        prompt_q "Step 1: Select the WAN interface"
        prompt_h "This port connects to the upstream Internet"
        prompt_h "(USB adapter or built-in Ethernet to the site's router)."
        WAN_IFACE=$(select_interface "Available interfaces:" "$WAN_IFACE")
        save_config_var "WAN_IFACE" "$WAN_IFACE"
        success "WAN Interface selected: $WAN_IFACE"
        
        prompt_q "Step 2: Select the LAN interface"
        prompt_h "This port hosts the secure private subnet"
        prompt_h "(e.g. built-in Ethernet to your Access Point)."
        prompt_hw "If you select Wi-Fi (wlan0), the Pi becomes a Wi-Fi Access Point."
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
                    prompt_q "❓ Install hostapd for Access Point?"
                    prompt_h "Wireless LAN requires hostapd (not installed)."
                    prompt_cue "[Y/n]"
                    if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
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

            if is_pkg_installed hostapd; then
                 success "'hostapd' is already installed."
                 INSTALL_HOSTAPD="false"
                 save_config_var "INSTALL_HOSTAPD" "false"
            else
                prompt_q "❓ Install hostapd for Access Point?"
                prompt_h "To use $LAN_IFACE for the private subnet, the Pi must act as a Wi-Fi AP."
                prompt_h "This requires installing hostapd (Host Access Point Daemon)."
                prompt_cue "[Y/n]"
                if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
                    error "Cannot proceed with wireless LAN without hostapd. Exiting."
                    exit 1
                fi
                INSTALL_HOSTAPD="true"
                save_config_var "INSTALL_HOSTAPD" "true"
            fi

            default_ssid="${AP_SSID:-}"
            while true; do
                prompt_q "📡 Access Point SSID (network name)"
                prompt_h "1–32 characters; no quotes, backslashes, or control characters."
                prompt_cue_default "SSID" "$default_ssid"
                input_ssid="$PROMPT_REPLY"
                if [ -z "$input_ssid" ] && [ -n "$default_ssid" ]; then
                    AP_SSID="$default_ssid"
                    break
                elif [ -n "$input_ssid" ]; then
                    if [ ${#input_ssid} -gt 32 ]; then
                        warn "SSID must be 32 characters or less."
                        continue
                    fi
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

            default_pass="${AP_PASS:-}"
            while true; do
                prompt_q "🔑 Access Point password"
                prompt_h "8–63 characters; no quotes, backslashes, or control characters."
                if [ -n "$default_pass" ]; then
                    prompt_h "Press Enter to keep the previously saved password."
                fi
                echo ""
                if [ -n "$default_pass" ]; then
                    echo -ne "   Password [default: ${BOLD}${YELLOW}********${NC}]: "
                else
                    echo -ne "   Password: "
                fi
                read -r -s input_pass < /dev/tty
                echo ""

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
                if echo "$input_pass" | grep -qE '["\x27\\]|[[:cntrl:]]'; then
                    warn "Password cannot contain quotes, backslashes, or control characters."
                    echo "[DEBUG] Password contains invalid characters." >> "$LOG_FILE"
                    continue
                fi
                AP_PASS="$input_pass"
                break
            done
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
        # PI_BYPASS_ROUTING may be unset on legacy installs; ask explicitly the
        # first time so we never rewrite an existing wg0.conf without consent.
        if [ -z "${PI_BYPASS_ROUTING:-}" ]; then
            prompt_pi_bypass_routing
        else
            info "Pi-bypass routing: ${PI_BYPASS_ROUTING} (from saved config)."
        fi
        # Dual-DNS plane: only meaningful when Pi-bypass is on. Reuse saved
        # values where present (using ${VAR+x} so we distinguish "never set"
        # from "set to empty"). Backward-compat for legacy configs that have
        # only HOME_DNS_SERVERS but no HOME_DNS_MODE.
        if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
            infer_home_dns_mode_legacy
            if [ -z "${HOME_DNS_MODE+x}" ]; then
                prompt_home_dns
            else
                local saved_dns_label="${HOME_DNS_MODE}"
                [ "$HOME_DNS_MODE" = "custom" ] && saved_dns_label="custom -> ${HOME_DNS_SERVERS:-<unset>}"
                [ "$HOME_DNS_MODE" = "tunnel" ] && saved_dns_label="tunnel-exit (${HOME_DNS_TUNNEL_DEFAULTS} via wg0)"
                info "LAN client DNS: ${saved_dns_label} (from saved config)."
            fi
            if [ -z "${PI_DNS_SERVERS+x}" ]; then
                prompt_pi_dns
            else
                info "Pi-local DNS: '${PI_DNS_SERVERS:-<none>}' (from saved config)."
            fi
        fi
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
        prompt_q "🛡️  Configure WAN firewall?"
        prompt_h "Allow SSH + WireGuard inbound; drop other unsolicited WAN traffic."
        prompt_cue "[Y/n]"
        if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
            FIREWALL_ENABLED="false"
        else
            FIREWALL_ENABLED="true"
        fi
        save_config_var "FIREWALL_ENABLED" "$FIREWALL_ENABLED"

        # Ask about automatic updates (logs only, no email)
        prompt_q "🔄 Enable automatic updates?"
        prompt_h "Installs unattended-upgrades; runs nightly around 03:00."
        prompt_cue "[Y/n]"
        if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
            AUTO_UPDATES_ENABLED="false"
        else
            AUTO_UPDATES_ENABLED="true"
        fi
        save_config_var "AUTO_UPDATES_ENABLED" "$AUTO_UPDATES_ENABLED"

        echo ""
        prompt_q "🛠️  Enable hardware watchdog?"
        prompt_h "Kernel-level auto-reboot if the system hangs (bcm2835 watchdog)."
        prompt_cue "[Y/n]"
        if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
            WATCHDOG_ENABLED="false"
        else
            WATCHDOG_ENABLED="true"
        fi
        save_config_var "WATCHDOG_ENABLED" "$WATCHDOG_ENABLED"

        # Pi-bypass routing: forwarded LAN -> wg0, Pi-local -> WAN.
        # Default Yes (strongly recommended); persisted so re-runs reuse it.
        prompt_pi_bypass_routing

        # Dual-DNS plane (Option A): home DNS for LAN clients, public DNS for
        # the Pi itself. Only meaningful when Pi-bypass routing is enabled.
        if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
            prompt_home_dns
            prompt_pi_dns
        fi
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
    if [ "${PI_BYPASS_ROUTING:-false}" = "true" ] && [ -n "${PI_DNS_SERVERS:-}" ]; then
        progress_add_step "Configure Pi-local DNS" "($PI_DNS_SERVERS via WAN)"
    fi
    case "${HOME_DNS_MODE:-skip}" in
        tunnel) progress_add_step "Configure DHCP server" "(dnsmasq -> tunnel-exit)" ;;
        custom) progress_add_step "Configure DHCP server" "(dnsmasq -> $HOME_DNS_SERVERS)" ;;
        *)      progress_add_step "Configure DHCP server" "(dnsmasq, WAN DNS)" ;;
    esac
    
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
        prompt_q "Proceed with setup?"
        prompt_h "After this, setup runs unattended (survives SSH/Pi Connect disconnect)."
        prompt_cue "[Y/n]"
        if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
            warn "Aborting setup by user request."
            exit 1
        fi
        APPLYING_CHANGES=true
    fi
    
    # Reset box line count - the prompt invalidated our cursor position
    PROGRESS_BOX_LINES=0
    echo ""

    # --- Boundary: input -> execution ---
    # All user input has been collected. Detach from the controlling terminal
    # so a dropped SSH / Pi Connect / serial session cannot kill us mid-step
    # and leave the Pi in a half-configured state. After this point, NOTHING
    # in the script may prompt the user.
    become_unattended

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

    # Configure Pi-local DNS (Option A: dual-DNS plane). Must run before
    # dnsmasq is restarted - 'no-resolv' in dnsmasq.conf relies on
    # PI_DNS_SERVERS being installed in /etc/resolv.conf for the Pi itself.
    if [ "${PI_BYPASS_ROUTING:-false}" = "true" ] && [ -n "${PI_DNS_SERVERS:-}" ]; then
        progress_run_step "Configure Pi-local DNS" "do_configure_pi_dns"
    fi

    # Configure dnsmasq
    progress_run_step "Configure DHCP server" "do_configure_dnsmasq"
    
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

    ui_echo ""
    ui_echo "${GREEN}${BOLD}🎉 Setup Complete!${NC}"
    ui_echo ""
    ui_echo "${GREEN}✔${NC} Status:"
    ui_echo "   • WAN Interface: ${BOLD}$WAN_IFACE${NC}"
    ui_echo "   • LAN Interface: ${BOLD}$LAN_IFACE${NC} (Gateway: $LAN_GATEWAY)"
    ui_echo "   • VPN Interface: ${BOLD}wg0${NC}"
    ui_echo ""
    ui_echo "${BLUE}ℹ️${NC}  Setup log saved to: $LOG_FILE"
    
    save_config
    ui_echo "${BLUE}ℹ️${NC}  Configuration saved to: $CONFIG_FILE"
}

main
