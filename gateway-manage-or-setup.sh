#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$ROOT_DIR/scripts"
SETUP_SCRIPT="$SCRIPTS_DIR/setup-vpn-gateway.sh"
CLEANUP_SCRIPT="$SCRIPTS_DIR/cleanup-gateway.sh"
CONFIG_FILE="$ROOT_DIR/vpn-gateway.conf"
LEGACY_CONFIG_1="$ROOT_DIR/gateway.conf"
LEGACY_CONFIG_2="$ROOT_DIR/vpn_gateway.conf"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--setup|--cleanup|--start|--stop|--yes|--help]

Runs the gateway setup or cleanup flows by dispatching to the scripts under $SCRIPTS_DIR.
Also supports starting/stopping the WireGuard gateway service. If no flag is provided,
an interactive prompt is shown.

Flags:
  --yes / --non-interactive   Run without prompts when possible (uses existing config; prompts only for missing values)
  --setup / --cleanup / --start / --stop
EOF
}

print_banner() {
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

            Site2Site Gateway — using WireGuard on Raspberry Pi
EOF
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
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet wg-quick@wg0
        return
    fi

    if command -v wg >/dev/null 2>&1; then
        wg show wg0 >/dev/null 2>&1
        return
    fi

    ip link show wg0 >/dev/null 2>&1
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

prompt_choice() {
    ensure_config_migrated

    local configured=false
    local active=false

    if is_config_present; then configured=true; fi
    if is_wg_active; then active=true; fi

    if [ "$configured" = false ] && [ "$active" = false ]; then
        echo "No existing gateway configuration detected. Launching setup..."
        run_setup
        return
    fi

    echo "Gateway status:"
    if [ "$configured" = true ]; then
        echo "  - Config: present at $CONFIG_FILE"
    else
        echo "  - Config: not found"
    fi
    if [ "$active" = true ]; then
        echo "  - WireGuard: active (wg0)"
    else
        echo "  - WireGuard: inactive"
    fi
    echo ""
    echo "Select an action:"
    echo "  1) Edit/reconfigure gateway (rerun setup)"
    echo "  2) Cleanup/restore gateway"
    echo "  3) Start gateway (WireGuard)"
    echo "  4) Stop gateway (WireGuard)"
    echo "  q) Quit"
    echo -n "Choice [1/2/3/4/q]: "
    read -r choice

    case "$choice" in
        1|"") run_setup ;;
        2) run_cleanup ;;
        3) run_start ;;
        4) run_stop ;;
        q|Q) echo "Exiting."; exit 0 ;;
        *) echo "Invalid choice."; prompt_choice ;;
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
    --cleanup|-c)
        run_cleanup
        ;;
    --start)
        run_start
        ;;
    --stop)
        run_stop
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

