#!/bin/bash

set -o pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$ROOT_DIR/scripts"
SETUP_SCRIPT="$SCRIPTS_DIR/setup-vpn-gateway.sh"
CLEANUP_SCRIPT="$SCRIPTS_DIR/cleanup-gateway.sh"
CONFIG_FILE="$ROOT_DIR/vpn-gateway.conf"
LEGACY_CONFIG_1="$ROOT_DIR/gateway.conf"
LEGACY_CONFIG_2="$ROOT_DIR/vpn_gateway.conf"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--setup|--cleanup|--help]

Runs the gateway setup or cleanup flows by dispatching to the scripts under $SCRIPTS_DIR.
If no flag is provided, an interactive prompt is shown.
EOF
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
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wg-quick@wg0; then
        return 0
    fi
    ip link show wg0 >/dev/null 2>&1
}

is_config_present() {
    [ -f "$CONFIG_FILE" ]
}

run_setup() {
    cd "$ROOT_DIR" && bash "$SETUP_SCRIPT"
}

run_cleanup() {
    cd "$ROOT_DIR" && bash "$CLEANUP_SCRIPT"
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
    echo "  q) Quit"
    echo -n "Choice [1/2/q]: "
    read -r choice

    case "$choice" in
        1|"") run_setup ;;
        2) run_cleanup ;;
        q|Q) echo "Exiting."; exit 0 ;;
        *) echo "Invalid choice."; prompt_choice ;;
    esac
}

if [ ! -f "$SETUP_SCRIPT" ] || [ ! -f "$CLEANUP_SCRIPT" ]; then
    echo "Required scripts not found under $SCRIPTS_DIR"
    exit 1
fi

ensure_config_migrated

case "$1" in
    --setup|-s)
        run_setup
        ;;
    --cleanup|-c)
        run_cleanup
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

