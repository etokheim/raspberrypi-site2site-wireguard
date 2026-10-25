# Sourced helpers: IPv4 routed site-to-site access, independent of Internet mode.
# Missing fields ALWAYS mean legacy NAT, including --apply / --start.
infer_site_routing_legacy() {
    SITE_ROUTING_MODE="${SITE_ROUTING_MODE:-nat}"
    SITE_REMOTE_CIDRS="${SITE_REMOTE_CIDRS:-}"
    SITE_INBOUND_ACCESS="${SITE_INBOUND_ACCESS:-outbound}"
    SITE_INBOUND_SOURCES="${SITE_INBOUND_SOURCES:-}"
}

validate_site_routing() {
    [ "${SITE_ROUTING_MODE:-nat}" = nat ] && return 0
    command -v python3 >/dev/null 2>&1 || {
        echo 'Site routing needs python3. Install it first: sudo apt-get install python3' >&2
        return 1
    }
    local wan
    wan=$(ip -o -4 addr show dev "$WAN_IFACE" 2>/dev/null | awk '{print $4}')
    if [ "${WAN_STATIC_IP_ENABLED:-false}" = true ]; then
        wan="$wan ${WAN_STATIC_IP}/${WAN_STATIC_PREFIX}"
    fi
    [ -n "$wan" ] || {
        echo 'Cannot check WAN overlap: connect the WAN interface or configure its static IP first.' >&2
        return 1
    }
    python3 "$SCRIPT_DIR/validate-site-routing.py" "${SITE_ROUTING_MODE:-nat}" \
        "$LAN_CIDR" "${SITE_REMOTE_CIDRS:-}" "${SITE_INBOUND_ACCESS:-outbound}" \
        "${SITE_INBOUND_SOURCES:-}" "${1:-${WG_CONF_SRC:-${WG_CONF_PATH:-}}}" \
        "$wan" "$LAN_IFACE" "$WAN_IFACE" "${PI_BYPASS_ROUTING:-false}"
}

site_routing_instructions() {
    echo "Pi-side LAN: $LAN_CIDR (devices plugged into this Pi)."
    echo "VPN-server-side networks: ${SITE_REMOTE_CIDRS:-not selected} (devices behind the VPN server, including other sites)."
    echo 'External VPN-server-side work is required; this script changes only the Pi:'
    echo "  On the server's peer for this Pi, set Networks behind client / AllowedIPs to include $LAN_CIDR."
    echo "  Route $LAN_CIDR to this Pi peer; allow forwarding and return traffic on the VPN server/router."
    echo "  If using UniFi Site Magic, advertise $LAN_CIDR from the VPN-server-side gateway to the other sites."
    echo '  Other site routers must route it back there; avoid overlaps. Allow traffic in device firewalls too.'
    echo '  Use this Pi as the Pi-side devices’ default gateway (or add return routes via this Pi).'
    echo 'IPv4 only: IPv6 site routing/firewall/NAT exemptions are NOT configured by this feature.'
}

prompt_site_routing() {
    local default="${SITE_ROUTING_MODE:-nat}" choice
    local previous_mode="$default"
    [ "${SITE_NEW_INSTALL:-false}" = true ] && default=routed
    prompt_q 'How should devices on the two sides connect?'
    prompt_h 'Pi-side = devices plugged into this Pi. VPN-server-side = devices behind your VPN server (and its other sites).'
    prompt_h '1) TWO-WAY (recommended for new installs): keep real device addresses; needs routes on the VPN-server-side.'
    prompt_h '2) OUTBOUND NAT (legacy): Pi-side devices connect out; VPN-server-side devices cannot start connections back.'
    prompt_h 'Saved installs keep legacy NAT until you explicitly choose TWO-WAY here. Internet forwarding is a separate setting.'
    if [ "${NONINTERACTIVE:-false}" = true ]; then
        # Never invent site networks from a default AllowedIPs or silently migrate.
        SITE_ROUTING_MODE="$default"
    else
        choice=2; [ "$default" = routed ] && choice=1
        prompt_cue_default 'Choice' "$choice"
        case "${PROMPT_REPLY:-$choice}" in
            1) SITE_ROUTING_MODE=routed ;;
            2) SITE_ROUTING_MODE=nat ;;
            *) echo 'Choose 1 or 2.' >&2; return 1 ;;
        esac
    fi
    if [ "$SITE_ROUTING_MODE" = routed ]; then
        PI_BYPASS_ROUTING=true
        [ "$previous_mode" = routed ] || SITE_INBOUND_ACCESS=sites
        site_routing_instructions
        if [ "${NONINTERACTIVE:-false}" != true ]; then
            prompt_q 'Which VPN-server-side IPv4 networks should use the tunnel?'
            prompt_h 'Ask the VPN-server-side administrator for the networks. Example: 192.168.20.0/24 192.168.30.0/24'
            prompt_h 'Do not enter the Pi-side LAN, WAN subnet, or 0.0.0.0/0. AllowedIPs alone does not choose these networks.'
            prompt_cue_default 'CIDRs' "${SITE_REMOTE_CIDRS:-}"
            SITE_REMOTE_CIDRS="${PROMPT_REPLY:-${SITE_REMOTE_CIDRS:-}}"
            prompt_q 'Who may start connections from the VPN-server-side into the Pi-side LAN?'
            prompt_h '1) Selected networks above (recommended): all protocols in both directions between these sites and the Pi-side LAN.'
            prompt_h 'Trust devices in those selected networks: they may reach Pi-side services. This does not open access to arbitrary Internet peers.'
            prompt_h '2) Only specific source networks/devices: choose this for narrower inbound access.'
            prompt_h '3) Outbound only: keep real addresses and return routes, but block new inbound connections.'
            choice=1
            case "${SITE_INBOUND_ACCESS:-sites}" in restricted) choice=2 ;; outbound) choice=3 ;; esac
            prompt_cue_default 'Choice' "$choice"
            case "${PROMPT_REPLY:-$choice}" in
                1) SITE_INBOUND_ACCESS=sites; SITE_INBOUND_SOURCES='' ;;
                2)
                    SITE_INBOUND_ACCESS=restricted
                    prompt_q 'Which VPN-server-side source networks or devices may connect?'
                    prompt_h 'Use CIDRs inside the selected networks; a single device uses /32, for example 192.168.20.5/32.'
                    prompt_cue_default 'Source CIDRs' "${SITE_INBOUND_SOURCES:-}"
                    SITE_INBOUND_SOURCES="${PROMPT_REPLY:-${SITE_INBOUND_SOURCES:-}}"
                    ;;
                3) SITE_INBOUND_ACCESS=outbound; SITE_INBOUND_SOURCES='' ;;
                *) echo 'Choose 1, 2 or 3.' >&2; return 1 ;;
            esac
        fi
        # Save nothing until validation and explicit migration confirmation succeed.
        validate_site_routing || return 1
        if [ "${NONINTERACTIVE:-false}" != true ]; then
            prompt_q 'Have you arranged the VPN-server-side routes and access rules?'
            prompt_h "Without the server peer's Networks behind client = $LAN_CIDR and return routes, TWO-WAY will not work."
            prompt_h 'This changes Pi-side NAT for site traffic. Existing connections may need reconnecting.'
            prompt_cue '[y/N]'
            [[ "$PROMPT_REPLY" =~ ^[Yy]$ ]] || return 1
        fi
    fi
    local var
    for var in SITE_ROUTING_MODE SITE_REMOTE_CIDRS SITE_INBOUND_ACCESS SITE_INBOUND_SOURCES; do
        save_config_var "$var" "${!var:-}"
    done
    [ "$SITE_ROUTING_MODE" != routed ] || save_config_var PI_BYPASS_ROUTING true
}

# Dedicated chains allow removal even when saved subnets/interfaces have changed.
# NAT ACCEPT terminates POSTROUTING; RETURN here would still hit MASQUERADE.
_site_iptables_up_cmds() {
    [ "${SITE_ROUTING_MODE:-nat}" = routed ] || return 0
    local site source sources="${SITE_REMOTE_CIDRS//,/ }"
    [ "${SITE_INBOUND_ACCESS:-outbound}" != restricted ] || sources="${SITE_INBOUND_SOURCES//,/ }"
    echo 'iptables -N VPN_SITE_FWD 2>/dev/null || true'
    echo 'iptables -F VPN_SITE_FWD'
    echo "iptables -A VPN_SITE_FWD -i wg0 -o $LAN_IFACE -d $LAN_CIDR -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    if [ "${SITE_INBOUND_ACCESS:-outbound}" != outbound ]; then
        for source in $sources; do
            echo "iptables -A VPN_SITE_FWD -i wg0 -o $LAN_IFACE -s $source -d $LAN_CIDR -m conntrack --ctstate NEW -j ACCEPT"
        done
    fi
    echo "iptables -A VPN_SITE_FWD -i wg0 -o $LAN_IFACE -j DROP"
    echo 'iptables -C FORWARD -j VPN_SITE_FWD 2>/dev/null || iptables -I FORWARD 1 -j VPN_SITE_FWD'
    echo 'iptables -t nat -N VPN_SITE_NAT 2>/dev/null || true'
    echo 'iptables -t nat -F VPN_SITE_NAT'
    for site in ${SITE_REMOTE_CIDRS//,/ }; do
        echo "iptables -t nat -A VPN_SITE_NAT -s $LAN_CIDR -d $site -o wg0 -j ACCEPT"
        echo "iptables -t nat -A VPN_SITE_NAT -s $site -d $LAN_CIDR -o $LAN_IFACE -j ACCEPT"
    done
    # Reposition the jump before any existing wg0/WAN masquerade on re-runs.
    echo 'while iptables -t nat -D POSTROUTING -j VPN_SITE_NAT 2>/dev/null; do :; done'
    echo 'iptables -t nat -I POSTROUTING 1 -j VPN_SITE_NAT'
}

_site_iptables_down_cmds() {
    cat <<'EOF'
while iptables -D FORWARD -j VPN_SITE_FWD 2>/dev/null; do :; done
iptables -F VPN_SITE_FWD 2>/dev/null || true
iptables -X VPN_SITE_FWD 2>/dev/null || true
while iptables -t nat -D POSTROUTING -j VPN_SITE_NAT 2>/dev/null; do :; done
iptables -t nat -F VPN_SITE_NAT 2>/dev/null || true
iptables -t nat -X VPN_SITE_NAT 2>/dev/null || true
EOF
}

remove_site_routing_rules() {
    # Only fixed, repository-owned command strings; no user input or saved eval.
    local commands
    commands=$(_site_iptables_down_cmds)
    eval "$commands"
}
