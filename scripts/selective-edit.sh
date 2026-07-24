# selective-edit.sh
# Sourced by setup-vpn-gateway.sh. Interactive "change one setting" flow that
# only reapplies the subsystems that setting touches (not a full stack rebuild).
#
# Entry: run_selective_edit  (also: setup-vpn-gateway.sh --edit)

# Human-readable current value for the settings list.
_edit_setting_value() {
    case "$1" in
        wan_iface)     echo "${WAN_IFACE:-<unset>}" ;;
        lan_iface)     echo "${LAN_IFACE:-<unset>}" ;;
        lan_cidr)      echo "${LAN_CIDR:-<unset>}" ;;
        wg_conf)       echo "${WG_CONF_PATH:-<unset>}" ;;
        pi_bypass)     echo "${PI_BYPASS_ROUTING:-false}" ;;
        lan_forward)
            if [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
                echo "n/a (Pi-bypass off)"
            else
                echo "${LAN_FORWARD_MODE:-all}"
            fi
            ;;
        home_dns)
            case "${HOME_DNS_MODE:-skip}" in
                custom) echo "custom → ${HOME_DNS_SERVERS:-?}" ;;
                tunnel) echo "tunnel-exit (${HOME_DNS_TUNNEL_DEFAULTS:-1.1.1.1 8.8.8.8})" ;;
                *)      echo "skip (WAN DNS)" ;;
            esac
            ;;
        pi_dns)        echo "${PI_DNS_SERVERS:-<unset>}" ;;
        wan_static)
            if [ "${WAN_STATIC_IP_ENABLED:-false}" = "true" ]; then
                echo "${WAN_STATIC_IP:-?}/${WAN_STATIC_PREFIX:-24}"
            else
                echo "disabled"
            fi
            ;;
        firewall)      echo "${FIREWALL_ENABLED:-true}" ;;
        auto_updates)  echo "${AUTO_UPDATES_ENABLED:-false}" ;;
        watchdog)      echo "${WATCHDOG_ENABLED:-false}" ;;
        *)             echo "?" ;;
    esac
}

_edit_print_menu() {
    echo ""
    echo -e "${BOLD}Change one setting${NC}"
    echo -e "${DIM}Only the subsystems that setting needs will be reapplied.${NC}"
    echo ""
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "1"  "WAN interface"        "$(_edit_setting_value wan_iface)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "2"  "LAN interface"        "$(_edit_setting_value lan_iface)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "3"  "LAN subnet (CIDR)"    "$(_edit_setting_value lan_cidr)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "4"  "WireGuard config"     "$(_edit_setting_value wg_conf)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "5"  "Pi-bypass routing"    "$(_edit_setting_value pi_bypass)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "6"  "LAN forward mode"     "$(_edit_setting_value lan_forward)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "7"  "LAN DNS (HOME_DNS)"   "$(_edit_setting_value home_dns)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "8"  "Pi DNS"               "$(_edit_setting_value pi_dns)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "9"  "WAN static IP"        "$(_edit_setting_value wan_static)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "10" "WAN firewall"         "$(_edit_setting_value firewall)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "11" "Auto-updates"         "$(_edit_setting_value auto_updates)"
    printf "   ${CYAN}%2s)${NC} %-22s ${DIM}%s${NC}\n" "12" "Hardware watchdog"    "$(_edit_setting_value watchdog)"
    echo ""
    echo -e "   ${DIM}q)${NC} Cancel"
    echo ""
}

# Prompt only for the chosen setting. Sets EDIT_KEY on success.
_edit_prompt_setting() {
    local key="$1"
    EDIT_KEY="$key"
    case "$key" in
        wan_iface)
            prompt_q "Select the WAN interface"
            prompt_h "Upstream Internet port."
            WAN_IFACE=$(select_interface "Available interfaces:" "$WAN_IFACE" "" "wan")
            save_config_var "WAN_IFACE" "$WAN_IFACE"
            ;;
        lan_iface)
            prompt_q "Select the LAN interface"
            prompt_h "Private subnet / AP port."
            LAN_IFACE=$(select_interface "Available interfaces:" "$LAN_IFACE" "$WAN_IFACE" "lan")
            save_config_var "LAN_IFACE" "$LAN_IFACE"
            if echo "$LAN_IFACE" | grep -q "wlan"; then
                IS_WIRELESS=true
            else
                IS_WIRELESS=false
            fi
            save_config_var "IS_WIRELESS" "$IS_WIRELESS"
            if [ "$IS_WIRELESS" = true ] || [ "$IS_WIRELESS" = "true" ]; then
                # Re-ask AP credentials if wireless
                prompt_q "Wi-Fi AP SSID"
                prompt_h "Name broadcast for the Pi access point."
                prompt_cue_default "SSID" "${AP_SSID:-PiVPN}"
                AP_SSID="${PROMPT_REPLY:-${AP_SSID:-PiVPN}}"
                save_config_var "AP_SSID" "$AP_SSID"
                prompt_q "Wi-Fi AP password"
                prompt_h "WPA2 passphrase (8+ characters)."
                prompt_cue_default "Password" "${AP_PASS:-}"
                AP_PASS="${PROMPT_REPLY:-$AP_PASS}"
                save_config_var "AP_PASS" "$AP_PASS"
            fi
            ;;
        lan_cidr)
            LAN_CIDR=$(get_ip_range)
            save_config_var "LAN_CIDR" "$LAN_CIDR"
            ;;
        wg_conf)
            WG_CONF_SRC=$(get_wg_config)
            WG_CONF_PATH="$WG_CONF_SRC"
            save_config_var "WG_CONF_PATH" "$WG_CONF_PATH"
            ;;
        pi_bypass)
            prompt_pi_bypass_routing
            if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
                prompt_lan_forward_mode
            fi
            ;;
        lan_forward)
            if [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
                warn "Pi-bypass is off — enable it first (option 5), or LAN forward mode has no effect."
                prompt_pi_bypass_routing
            fi
            if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
                prompt_lan_forward_mode
            else
                return 1
            fi
            ;;
        home_dns)
            if [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
                warn "LAN DNS plane only applies with Pi-bypass enabled."
                prompt_pi_bypass_routing
            fi
            if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
                prompt_home_dns
            else
                return 1
            fi
            ;;
        pi_dns)
            if [ "${PI_BYPASS_ROUTING:-false}" != "true" ]; then
                warn "Pi DNS plane only applies with Pi-bypass enabled."
                prompt_pi_bypass_routing
            fi
            if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
                prompt_pi_dns
            else
                return 1
            fi
            ;;
        wan_static)
            prompt_wan_static_ip
            ;;
        firewall)
            prompt_q "🛡️  Configure WAN firewall?"
            prompt_h "Allow SSH + WireGuard inbound; drop other unsolicited WAN traffic."
            local cue="[Y/n]"
            [ "${FIREWALL_ENABLED:-true}" = "false" ] && cue="[y/N]"
            prompt_cue "$cue"
            if [ "${FIREWALL_ENABLED:-true}" = "true" ]; then
                [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]] && FIREWALL_ENABLED="false" || FIREWALL_ENABLED="true"
            else
                [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] && FIREWALL_ENABLED="true" || FIREWALL_ENABLED="false"
            fi
            save_config_var "FIREWALL_ENABLED" "$FIREWALL_ENABLED"
            ;;
        auto_updates)
            prompt_q "🔄 Enable automatic updates?"
            prompt_h "Installs unattended-upgrades; runs nightly around 03:00."
            local cue="[y/N]"
            [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ] && cue="[Y/n]"
            prompt_cue "$cue"
            if [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ]; then
                [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]] && AUTO_UPDATES_ENABLED="false" || AUTO_UPDATES_ENABLED="true"
            else
                [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] && AUTO_UPDATES_ENABLED="true" || AUTO_UPDATES_ENABLED="false"
            fi
            save_config_var "AUTO_UPDATES_ENABLED" "$AUTO_UPDATES_ENABLED"
            ;;
        watchdog)
            prompt_q "🛠️  Enable hardware watchdog?"
            prompt_h "Kernel-level auto-reboot if the system hangs (bcm2835 watchdog)."
            local cue="[y/N]"
            [ "${WATCHDOG_ENABLED:-false}" = "true" ] && cue="[Y/n]"
            prompt_cue "$cue"
            if [ "${WATCHDOG_ENABLED:-false}" = "true" ]; then
                [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]] && WATCHDOG_ENABLED="false" || WATCHDOG_ENABLED="true"
            else
                [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] && WATCHDOG_ENABLED="true" || WATCHDOG_ENABLED="false"
            fi
            save_config_var "WATCHDOG_ENABLED" "$WATCHDOG_ENABLED"
            ;;
        *)
            error "Unknown setting: $key"
            return 1
            ;;
    esac
    return 0
}

# Derive LAN_GATEWAY from LAN_CIDR (used after CIDR / iface edits).
_edit_refresh_lan_gateway() {
    local prefix
    prefix=$(echo "${LAN_CIDR:-}" | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3}')
    if echo "$prefix" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        LAN_GATEWAY="${prefix}.1"
    fi
    WG_CONF_SRC="${WG_CONF_PATH:-$WG_CONF_SRC}"
    WG_CONF_DEST="${WG_CONF_DEST:-/etc/wireguard/wg0.conf}"
}

# Apply only what EDIT_KEY requires. Uses progress box + optional detach.
_edit_apply_setting() {
    local key="$1"
    _edit_refresh_lan_gateway

    progress_clear
    APPLYING_CHANGES=true

    case "$key" in
        wan_iface)
            progress_add_step "Update NAT / firewall for WAN"
            progress_add_step "Verify routing"
            ;;
        lan_iface|lan_cidr)
            progress_add_step "Configure LAN interface"
            progress_add_step "Configure DHCP server"
            [ "${IS_WIRELESS:-false}" = "true" ] || [ "${IS_WIRELESS:-}" = true ] && \
                progress_add_step "Configure Access Point"
            progress_add_step "Update WireGuard policy routing"
            progress_add_step "Reload WireGuard"
            progress_add_step "Verify routing"
            ;;
        wg_conf|pi_bypass|lan_forward)
            progress_add_step "Install WireGuard config"
            progress_add_step "Update WireGuard policy routing"
            progress_add_step "Reload WireGuard"
            if [ "$key" = "pi_bypass" ] && [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
                progress_add_step "Configure Pi-local DNS"
                progress_add_step "Configure DHCP server"
            fi
            progress_add_step "Verify routing"
            ;;
        home_dns)
            progress_add_step "Configure DHCP server"
            progress_add_step "Verify routing"
            ;;
        pi_dns)
            progress_add_step "Configure Pi-local DNS"
            progress_add_step "Verify routing"
            ;;
        wan_static)
            progress_add_step "Configure WAN static IP"
            ;;
        firewall)
            progress_add_step "Update WAN firewall"
            ;;
        auto_updates)
            progress_add_step "Configure auto-updates"
            ;;
        watchdog)
            progress_add_step "Configure hardware watchdog"
            ;;
    esac

    progress_draw_box
    prompt_q "Apply this change?"
    prompt_h "Only the steps listed above will run."
    prompt_cue "[Y/n]"
    if [[ "$PROMPT_REPLY" =~ ^[Nn]$ ]]; then
        warn "Aborted — config file was updated but live system was not changed."
        warn "Re-run apply later, or restore values in $CONFIG_FILE."
        exit 1
    fi
    APPLYING_CHANGES=true
    PROGRESS_BOX_LINES=0
    echo ""

    # Detach for network-disruptive changes only.
    case "$key" in
        lan_iface|lan_cidr|wg_conf|pi_bypass|lan_forward|wan_iface|wan_static)
            become_unattended
            ;;
    esac

    case "$key" in
        wan_iface)
            progress_run_step "Update NAT / firewall for WAN" "
                ensure_nat_rules
                if [ \"${FIREWALL_ENABLED:-true}\" = true ]; then
                    ensure_wan_firewall_rules
                else
                    remove_tagged_input_rules
                fi
                persist_iptables_rules
            "
            if [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
                progress_run_step "Verify routing" "do_verify_routes"
            else
                progress_skip_step "Verify routing"
            fi
            ;;
        lan_iface|lan_cidr)
            if [ -n "${PREV_LAN_IFACE:-}" ] && [ "$PREV_LAN_IFACE" != "$LAN_IFACE" ]; then
                reset_previous_lan_iface "$PREV_LAN_IFACE" "$LAN_IFACE" "${PREV_IS_WIRELESS:-false}"
            fi
            progress_run_step "Configure LAN interface" "do_configure_lan_interface"
            progress_run_step "Configure DHCP server" "do_configure_dnsmasq"
            if [ "${IS_WIRELESS:-false}" = "true" ] || [ "${IS_WIRELESS:-}" = true ]; then
                progress_run_step "Configure Access Point" "do_configure_hostapd"
            fi
            WG_PREV_HASH=""
            if [ -f "$WG_CONF_DEST" ]; then
                WG_PREV_HASH=$(sha256sum "$WG_CONF_DEST" | awk '{print $1}')
            fi
            # Force rewrite of PostUp (iif=LAN) even if peer file unchanged.
            progress_run_step "Update WireGuard policy routing" "
                cp \"\$WG_CONF_SRC\" \"\$WG_CONF_DEST\" && chmod 600 \"\$WG_CONF_DEST\"
                do_configure_wg_firewall_rules
            "
            # Force restart so new iif rule applies.
            WG_PREV_HASH="force-reload"
            progress_run_step "Reload WireGuard" "do_start_wireguard"
            ensure_nat_rules
            persist_iptables_rules
            progress_run_step "Verify routing" "do_verify_routes"
            ;;
        wg_conf|pi_bypass|lan_forward)
            WG_PREV_HASH=""
            if [ -f "$WG_CONF_DEST" ]; then
                WG_PREV_HASH=$(sha256sum "$WG_CONF_DEST" | awk '{print $1}')
            fi
            progress_run_step "Install WireGuard config" "cp \"$WG_CONF_SRC\" \"$WG_CONF_DEST\" && chmod 600 \"$WG_CONF_DEST\""
            progress_run_step "Update WireGuard policy routing" "do_configure_wg_firewall_rules"
            progress_run_step "Reload WireGuard" "do_start_wireguard"
            if [ "$key" = "pi_bypass" ] && [ "${PI_BYPASS_ROUTING:-false}" = "true" ]; then
                if [ -n "${PI_DNS_SERVERS:-}" ]; then
                    progress_run_step "Configure Pi-local DNS" "do_configure_pi_dns"
                fi
                progress_run_step "Configure DHCP server" "do_configure_dnsmasq"
            fi
            ensure_nat_rules
            persist_iptables_rules
            progress_run_step "Verify routing" "do_verify_routes"
            ;;
        home_dns)
            progress_run_step "Configure DHCP server" "do_configure_dnsmasq"
            progress_run_step "Verify routing" "do_verify_routes"
            ;;
        pi_dns)
            progress_run_step "Configure Pi-local DNS" "do_configure_pi_dns"
            progress_run_step "Verify routing" "do_verify_routes"
            ;;
        wan_static)
            if [ "${WAN_STATIC_IP_ENABLED:-false}" = "true" ]; then
                progress_run_step "Configure WAN static IP" "do_configure_wan_static_ip"
            else
                progress_set_status "$(progress_find_step "Configure WAN static IP")" "skip" "(disabled)"
                progress_draw_box
                info "WAN static IP disabled — not changing live address (set via DHCP/NM as before)."
            fi
            ;;
        firewall)
            progress_run_step "Update WAN firewall" "
                if [ \"${FIREWALL_ENABLED:-true}\" = true ]; then
                    ensure_wan_firewall_rules
                else
                    remove_tagged_input_rules
                fi
                persist_iptables_rules
            "
            ;;
        auto_updates)
            if [ "${AUTO_UPDATES_ENABLED:-false}" = "true" ]; then
                progress_run_step "Configure auto-updates" "do_configure_auto_updates"
            else
                progress_set_status "$(progress_find_step "Configure auto-updates")" "done" "(left disabled)"
                progress_draw_box
                info "Auto-updates left disabled (existing timers not removed)."
            fi
            ;;
        watchdog)
            if [ "${WATCHDOG_ENABLED:-false}" = "true" ]; then
                progress_run_step "Configure hardware watchdog" "do_hardware_watchdog_setup"
            else
                progress_set_status "$(progress_find_step "Configure hardware watchdog")" "done" "(left disabled)"
                progress_draw_box
                info "Hardware watchdog left disabled."
            fi
            ;;
    esac

    progress_draw_box
    ui_echo ""
    ui_echo "${GREEN}${BOLD}✔ Setting updated${NC} (${key})"
    ui_echo "${BLUE}ℹ️${NC}  Log: $LOG_FILE"
    ui_echo "${BLUE}ℹ️${NC}  Config: $CONFIG_FILE"
    if [ -n "${VERIFY_SUMMARY:-}" ]; then
        ui_echo "   Route checks: ${VERIFY_SUMMARY}"
    fi
}

run_selective_edit() {
    load_config
    NONINTERACTIVE=false
    init_log
    check_root
    print_header

    if ! has_full_config; then
        error "No complete gateway config found. Run full setup first."
        exit 1
    fi

    show_existing_config
    PREV_LAN_IFACE="$LAN_IFACE"
    PREV_WAN_IFACE="$WAN_IFACE"
    PREV_LAN_CIDR="$LAN_CIDR"
    PREV_IS_WIRELESS="${IS_WIRELESS:-false}"
    WG_CONF_SRC="${WG_CONF_PATH}"
    WG_CONF_DEST="/etc/wireguard/wg0.conf"
    _edit_refresh_lan_gateway

    local choice key=""
    while true; do
        _edit_print_menu
        echo -ne "   ${BOLD}Number:${NC} "
        read -r choice < /dev/tty
        case "$choice" in
            1) key="wan_iface" ;;
            2) key="lan_iface" ;;
            3) key="lan_cidr" ;;
            4) key="wg_conf" ;;
            5) key="pi_bypass" ;;
            6) key="lan_forward" ;;
            7) key="home_dns" ;;
            8) key="pi_dns" ;;
            9) key="wan_static" ;;
            10) key="firewall" ;;
            11) key="auto_updates" ;;
            12) key="watchdog" ;;
            q|Q|"") echo "Cancelled."; exit 0 ;;
            *) warn "Invalid choice."; continue ;;
        esac
        break
    done

    echo ""
    info "Editing: $key (current: $(_edit_setting_value "$key"))"
    if ! _edit_prompt_setting "$key"; then
        error "Could not update that setting."
        exit 1
    fi

    _edit_apply_setting "$key"
}
