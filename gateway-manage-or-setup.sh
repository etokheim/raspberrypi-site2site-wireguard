#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$ROOT_DIR/scripts"
SETUP_SCRIPT="$SCRIPTS_DIR/setup-vpn-gateway.sh"
CLEANUP_SCRIPT="$SCRIPTS_DIR/cleanup-gateway.sh"
CONFIG_FILE="$ROOT_DIR/vpn-gateway.conf"
LEGACY_CONFIG_1="$ROOT_DIR/gateway.conf"
LEGACY_CONFIG_2="$ROOT_DIR/vpn_gateway.conf"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $(basename "$0") [--setup|--edit|--apply|--cleanup|--start|--stop|--speedtest|--yes|--help]

Runs the gateway setup or cleanup flows by dispatching to the scripts under $SCRIPTS_DIR.
Also supports starting/stopping the WireGuard gateway, changing one setting,
applying a hand-edited config, and running a WAN-vs-tunnel Ookla speedtest.
If no flag is provided, an interactive prompt is shown.

Flags:
  --yes / --non-interactive   Run without prompts when possible (uses existing config; prompts only for missing values)
  --setup / --edit / --apply / --cleanup / --start / --stop / --speedtest
EOF
}

print_banner() {
    echo -e "${YELLOW}"
    cat <<'EOF'
               ('-.     .-') _     ('-.    (`\ .-') /`  ('-.                 
              ( OO ).-.(  OO) )  _(  OO)    `.( OO ),' ( OO ).-.             
  ,----.      / . --. //     '._(,------.,--./  .--.   / . --. /  ,--.   ,--.
 '  .-./-')   | \-.  \ |'--...__)|  .---'|      |  |   | \-.  \    \  `.'  / 
 |  |_( O- ).-'-'  |  |'--.  .--'|  |    |  |   |  |,.-'-'  |  | .-')     /  
 |  | .--, \ \| |_.'  |   |  |  (|  '--. |  |.'.|  |_)\| |_.'  |(OO  \   /   
(|  | '. (_/  |  .-.  |   |  |   |  .--' |         |   |  .-.  | |   /  /\_  
 |  '--'  |   |  | |  |   |  |   |  `---.|   ,'.   |   |  | |  | `-./  /.__) 
  `------'    `--' `--'   `--'   `------''--'   '--'   `--' `--'   `--'      
EOF
    echo -e "${NC}"
    echo -e "${BOLD}            Site2Site Gateway — using WireGuard on Raspberry Pi${NC}"
    echo ""
}

ensure_config_migrated() {
    if [ -f "$CONFIG_FILE" ]; then
        return
    fi
    if [ -f "$LEGACY_CONFIG_1" ]; then
        mv "$LEGACY_CONFIG_1" "$CONFIG_FILE"
    elif [ -f "$LEGACY_CONFIG_2" ]; then
        mv "$LEGACY_CONFIG_2" "$CONFIG_FILE"
    fi
}

is_wg_active() {
    # Check if the wg0 interface actually exists and is up (most reliable)
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

is_config_present() {
    [ -f "$CONFIG_FILE" ]
}

load_config_if_present() {
    ensure_config_migrated
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        . "$CONFIG_FILE"
    fi
}

run_setup() {
    cd "$ROOT_DIR" && NONINTERACTIVE="$NONINTERACTIVE" bash "$SETUP_SCRIPT"
}

run_edit() {
    load_config_if_present
    if ! is_config_present; then
        echo "No gateway config found at $CONFIG_FILE. Launching full setup..."
        run_setup
        return
    fi
    cd "$ROOT_DIR" && NONINTERACTIVE="$NONINTERACTIVE" bash "$SETUP_SCRIPT" --edit
}

# Re-apply vpn-gateway.conf as-is (for hand-edits or idempotent repair).
run_apply_saved() {
    load_config_if_present
    if ! is_config_present; then
        echo "No gateway config found at $CONFIG_FILE. Launching full setup..."
        run_setup
        return
    fi
    echo -e "${CYAN}Applying saved configuration from $CONFIG_FILE (no prompts)…${NC}"
    cd "$ROOT_DIR" && NONINTERACTIVE=true bash "$SETUP_SCRIPT"
}

run_cleanup() {
    cd "$ROOT_DIR" && NONINTERACTIVE="$NONINTERACTIVE" bash "$CLEANUP_SCRIPT"
}

run_start() {
    load_config_if_present
    if ! is_config_present; then
        echo "No gateway config found at $CONFIG_FILE. Launching setup..."
        run_setup
        return
    fi

    # Ensure LAN interface has its static IP (may not be set if systemd service didn't run)
    if [ -n "${LAN_IFACE:-}" ] && [ -n "${LAN_CIDR:-}" ]; then
        local lan_gw
        lan_gw=$(echo "$LAN_CIDR" | sed 's/\.0\/24$/.1/')
        if ! ip addr show dev "$LAN_IFACE" 2>/dev/null | grep -q "$lan_gw"; then
            echo "Setting LAN IP ($lan_gw) on $LAN_IFACE..."
            ip addr add "$lan_gw/24" dev "$LAN_IFACE" 2>/dev/null || true
            ip link set "$LAN_IFACE" up
        fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files 2>/dev/null | grep -q '^vpn-gateway-lan\.service'; then
            echo "Starting LAN readiness service (vpn-gateway-lan)..."
            # --wait blocks until the oneshot unit reports active (or fails).
            # Falls back to plain start if --wait is unsupported on this systemd.
            if ! systemctl start --wait vpn-gateway-lan.service >/dev/null 2>&1; then
                systemctl start vpn-gateway-lan.service >/dev/null 2>&1 || true
            fi
            if ! systemctl is-active --quiet vpn-gateway-lan.service; then
                echo "Warning: vpn-gateway-lan.service did not become active. Continuing." >&2
            fi
        else
            echo "Note: vpn-gateway-lan.service not installed yet. Run --setup to install boot-ordering units." >&2
        fi
    fi

    # Bring up AP/DHCP if configured for wireless
    if [ "${IS_WIRELESS:-false}" = "true" ]; then
        echo "Starting Access Point (hostapd)..."
        rfkill unblock wlan >/dev/null 2>&1 || true
        if ! systemctl start hostapd >/dev/null 2>&1; then
            echo "Failed to start hostapd" >&2
            return 1
        fi
    fi

    echo "Starting DHCP (dnsmasq)..."
    if ! systemctl start dnsmasq >/dev/null 2>&1; then
        echo "Failed to start dnsmasq" >&2
        return 1
    fi

    if is_wg_active; then
        echo "WireGuard (wg0) already active."
        return
    fi
    echo "Starting WireGuard (wg0)..."
    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl start wg-quick@wg0; then
            echo "Failed to start wg-quick@wg0" >&2
            return 1
        fi
        if ! systemctl enable wg-quick@wg0; then
            echo "Failed to enable wg-quick@wg0" >&2
            return 1
        fi
    else
        if ! wg-quick up wg0; then
            echo "Failed to bring up wg0 via wg-quick" >&2
            return 1
        fi
    fi
}

run_stop() {
    local status=0
    load_config_if_present

    if is_wg_active; then
        echo "Stopping WireGuard (wg0)..."
        if command -v systemctl >/dev/null 2>&1; then
            if ! systemctl stop wg-quick@wg0; then
                echo "Failed to stop wg-quick@wg0" >&2
                status=1
            fi
            if ! systemctl disable wg-quick@wg0; then
                echo "Failed to disable wg-quick@wg0" >&2
                status=1
            fi
        else
            # No systemd - use wg-quick directly
            if ! wg-quick down wg0 2>/dev/null; then
                echo "wg-quick down wg0 failed" >&2
                status=1
            fi
        fi
    else
        echo "WireGuard (wg0) is not active."
    fi

    # Stop AP if wireless was configured or hostapd is active
    if [ "${IS_WIRELESS:-false}" = "true" ] || systemctl is-active --quiet hostapd; then
        echo "Stopping Access Point (hostapd)..."
        if ! systemctl stop hostapd >/dev/null 2>&1; then
            echo "Failed to stop hostapd" >&2
            status=1
        fi
    fi

    echo "Stopping DHCP (dnsmasq)..."
    if ! systemctl stop dnsmasq >/dev/null 2>&1; then
        echo "Failed to stop dnsmasq" >&2
        status=1
    fi

    return $status
}

run_speedtest() {
    load_config_if_present
    if ! is_config_present; then
        echo "No gateway config found at $CONFIG_FILE. Run setup first."
        exit 1
    fi
    cd "$ROOT_DIR" && NONINTERACTIVE="$NONINTERACTIVE" bash "$SETUP_SCRIPT" --speedtest
}

prompt_choice() {
    ensure_config_migrated

    local configured=false
    local active=false

    if is_config_present; then configured=true; fi
    if is_wg_active; then active=true; fi

    if [ "$configured" = false ] && [ "$active" = false ]; then
        echo -e "${CYAN}No existing gateway configuration detected. Launching setup...${NC}"
        run_setup
        return
    fi

    # Status box - 76 chars wide total
    # │ = 1, space = 1, content, space = 1, │ = 1  => content area = 72 chars
    local box_w=76
    local content_w=$((box_w - 4))  # 72 chars for content (between "│ " and " │")
    local label_w=14  # "  ● Config:    " or "  ○ WireGuard: " visible prefix
    local field_w=$((content_w - label_w))  # 58 chars for field value
    local border
    border=$(printf '─%.0s' $(seq 1 $((box_w - 2))))
    
    echo -e "${CYAN}╭${border}╮${NC}"
    echo -e "${CYAN}│${NC} ${BOLD}Gateway Status${NC}$(printf '%*s' $((content_w - 14)) '') ${CYAN}│${NC}"
    echo -e "${CYAN}├${border}┤${NC}"
    if [ "$configured" = true ]; then
        # Truncate path if too long
        local config_display="$CONFIG_FILE"
        if [ ${#config_display} -gt $field_w ]; then
            config_display="...${config_display: -$((field_w - 3))}"
        fi
        printf "${CYAN}│${NC}  ${GREEN}●${NC} Config:    %-${field_w}s ${CYAN}│${NC}\n" "$config_display"
    else
        printf "${CYAN}│${NC}  ${RED}○${NC} Config:    %-${field_w}s ${CYAN}│${NC}\n" "not found"
    fi
    if [ "$active" = true ]; then
        printf "${CYAN}│${NC}  ${GREEN}●${NC} WireGuard: ${GREEN}%-${field_w}s${NC} ${CYAN}│${NC}\n" "active (wg0)"
    else
        printf "${CYAN}│${NC}  ${DIM}○${NC} WireGuard: %-${field_w}s ${CYAN}│${NC}\n" "inactive"
    fi
    echo -e "${CYAN}╰${border}╯${NC}"
    echo ""
    
    # Menu
    echo -e "${BOLD}Select an action:${NC}"
    echo ""
    echo -e "   ${CYAN}1)${NC} Edit/reconfigure gateway"
    echo -e "   ${RED}2)${NC} Remove the configured gateway"
    echo -e "   ${GREEN}3)${NC} Start gateway ${DIM}(WireGuard + services)${NC}"
    echo -e "   ${YELLOW}4)${NC} Stop gateway ${DIM}(WireGuard + services)${NC}"
    echo -e "   ${MAGENTA}5)${NC} Speedtest ${DIM}(WAN vs WireGuard tunnel)${NC}"
    echo -e "   ${DIM}q)${NC} Quit"
    echo ""
    echo -ne "${BOLD}Choice [1/2/3/4/5/q]:${NC} "
    read -r choice

    case "$choice" in
        1|"") prompt_edit_submenu ;;
        2) run_cleanup ;;
        3) run_start ;;
        4) run_stop ;;
        5) run_speedtest ;;
        q|Q) echo "Exiting."; exit 0 ;;
        *) echo -e "${RED}Invalid choice.${NC}"; prompt_choice ;;
    esac
}

prompt_edit_submenu() {
    echo ""
    echo -e "${BOLD}Edit / reconfigure${NC}"
    echo ""
    echo -e "   ${CYAN}1)${NC} Change one setting ${DIM}(only reapplies what that setting needs)${NC}"
    echo -e "   ${CYAN}2)${NC} Full reconfigure ${DIM}(walk through setup again)${NC}"
    echo -e "   ${CYAN}3)${NC} Apply saved configuration ${DIM}(vpn-gateway.conf as-is — for hand-edits)${NC}"
    echo -e "   ${DIM}b)${NC} Back"
    echo ""
    echo -ne "${BOLD}Choice [1/2/3/b]:${NC} "
    read -r sub
    case "$sub" in
        1|"") run_edit ;;
        2) run_setup ;;
        3) run_apply_saved ;;
        b|B) prompt_choice ;;
        *) echo -e "${RED}Invalid choice.${NC}"; prompt_edit_submenu ;;
    esac
}

if [ ! -f "$SETUP_SCRIPT" ] || [ ! -f "$CLEANUP_SCRIPT" ]; then
    echo "Required scripts not found under $SCRIPTS_DIR"
    exit 1
fi

print_banner
ensure_config_migrated

NONINTERACTIVE=false
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --yes|--non-interactive|-y) NONINTERACTIVE=true ;;
        *) ARGS+=("$arg") ;;
    esac
done

if [ ${#ARGS[@]} -gt 0 ]; then
    set -- "${ARGS[@]}"
else
    set --
fi

if [ $# -gt 1 ]; then
    echo "Too many arguments: $*" >&2
    usage
    exit 1
fi

case "${1:-}" in
    --setup|-s)
        run_setup
        ;;
    --edit|-e)
        run_edit
        ;;
    --apply)
        run_apply_saved
        ;;
    --cleanup|-c)
        run_cleanup
        ;;
    --start)
        run_start
        ;;
    --stop)
        run_stop
        ;;
    --speedtest)
        run_speedtest
        ;;
    --help|-h)
        usage
        ;;
    "")
        prompt_choice
        ;;
    *)
        echo "Unknown option: $1"
        usage
        exit 1
        ;;
esac

