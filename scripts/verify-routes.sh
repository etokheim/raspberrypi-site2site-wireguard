# verify-routes.sh
# Sourced by setup-vpn-gateway.sh. Simulates LAN-client and Pi-local lookups
# with `ip route get`, probes DNS reachability, and compares public egress
# IPs (WAN vs tunnel vs WireGuard Endpoint host).
#
# Expects: ui_echo, ui_printf, color vars, LAN_IFACE, WAN_IFACE, LAN_CIDR /
# LAN_GATEWAY, PI_BYPASS_ROUTING, LAN_FORWARD_MODE, HOME_DNS_*, PI_DNS_*,
# WG_CONF_DEST / WG_CONF_SRC, extract_home_subnets, cidr_family, LOG_FILE,
# HOME_DNS_TUNNEL_DEFAULTS (optional).

# Echo the first host IP (.1) of the first IPv4 home AllowedIPs subnet.
verify_first_home_host() {
    local cfg="${1:-${WG_CONF_DEST:-${WG_CONF_SRC:-}}}"
    local cidr base
    [ -n "$cfg" ] && [ -f "$cfg" ] || return 0
    while IFS= read -r cidr; do
        [ "$(cidr_family "$cidr")" = "4" ] || continue
        base=$(echo "$cidr" | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3}')
        if echo "$base" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "${base}.1"
            return 0
        fi
    done < <(extract_home_subnets "$cfg")
}

# Fake LAN client address for `ip route get ... from ... iif ...`.
verify_lan_client_ip() {
    local cidr="${LAN_CIDR:-}"
    local gw="${LAN_GATEWAY:-}"
    if [ -n "$gw" ]; then
        echo "$gw" | awk -F'.' '{print $1"."$2"."$3".10"}'
        return
    fi
    if [ -n "$cidr" ]; then
        echo "$cidr" | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3".10"}'
        return
    fi
    echo "10.10.10.10"
}

# Parse Endpoint host from a WireGuard conf (strips :port; handles [ipv6]).
verify_extract_endpoint_host() {
    local cfg="${1:-${WG_CONF_DEST:-${WG_CONF_SRC:-}}}"
    [ -f "$cfg" ] || return 0
    local ep
    ep=$(awk '
        /^[[:space:]]*Endpoint[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "", $0)
            gsub(/[[:space:]]/, "", $0)
            print $0
            exit
        }' "$cfg")
    [ -z "$ep" ] && return 0
    case "$ep" in
        \[*\]*)
            # [2001:db8::1]:51820
            echo "$ep" | sed -n 's/^\[\([^]]*\)\].*/\1/p'
            ;;
        *:*)
            # host:port or v4:port — strip trailing :digits only
            echo "$ep" | sed 's/:[0-9][0-9]*$//'
            ;;
        *)
            echo "$ep"
            ;;
    esac
}

verify_resolve_host() {
    local host="$1"
    [ -n "$host" ] || return 0
    # Literal IPv4
    if echo "$host" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "$host"
        return 0
    fi
    # Prefer getent, then dig
    local ip=""
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
    if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
        ip=$(dig +time=2 +tries=1 +short A "$host" 2>/dev/null | awk '/^[0-9]+\./{print; exit}')
    fi
    echo "$ip"
}

verify_public_ip_via() {
    local iface="${1:-}"
    local ip=""
    if [ -n "$iface" ]; then
        ip=$(curl -4 -s --max-time 8 --interface "$iface" https://api.ipify.org 2>/dev/null || true)
    else
        ip=$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null || true)
    fi
    echo "$ip"
}

# Parse `dev` from `ip route get` output. Echoes iface name or empty.
verify_route_dev() {
    ip route get "$@" 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit }
    }' | head -n1
}

# Classify egress: tunnel | wan | other | fail
verify_classify_dev() {
    local dev="$1"
    if [ -z "$dev" ]; then
        echo "fail"
    elif [ "$dev" = "wg0" ]; then
        echo "tunnel"
    elif [ -n "${WAN_IFACE:-}" ] && [ "$dev" = "$WAN_IFACE" ]; then
        echo "wan"
    else
        echo "other"
    fi
}

verify_expect_label() {
    case "$1" in
        tunnel) echo "via VPN tunnel (wg0)" ;;
        wan)    echo "via WAN (${WAN_IFACE:-wan})" ;;
        other)  echo "via $2" ;;
        fail)   echo "no route" ;;
    esac
}

verify_record() {
    local ok="$1"
    VERIFY_TOTAL_COUNT=$((VERIFY_TOTAL_COUNT + 1))
    if [ "$ok" = "1" ]; then
        VERIFY_PASS_COUNT=$((VERIFY_PASS_COUNT + 1))
        VERIFY_LAST_OK=1
    else
        VERIFY_FAIL_COUNT=$((VERIFY_FAIL_COUNT + 1))
        VERIFY_LAST_OK=0
    fi
}

# Args: description  dest  expected(tunnel|wan)  [from_ip]  [iif]
verify_one_route() {
    local desc="$1" dest="$2" expected="$3" from_ip="${4:-}" iif="${5:-}"
    local out_dev class ok_icon color note args=()

    if [ -n "$from_ip" ] && [ -n "$iif" ]; then
        args=("$dest" from "$from_ip" iif "$iif")
    else
        args=("$dest")
    fi

    out_dev=$(verify_route_dev "${args[@]}")
    class=$(verify_classify_dev "$out_dev")

    if [ "$class" = "$expected" ]; then
        ok_icon="✔"
        color="${GREEN}"
        verify_record 1
    else
        ok_icon="✖"
        color="${RED}"
        verify_record 0
    fi

    note=$(verify_expect_label "$class" "$out_dev")
    local expect_note
    expect_note=$(verify_expect_label "$expected" "")

    ui_echo "   ${color}${ok_icon}${NC} ${BOLD}${desc}${NC}"
    ui_echo "      dest ${DIM}${dest}${NC}  →  ${BOLD}${note}${NC}"
    if [ "$VERIFY_LAST_OK" != "1" ]; then
        ui_echo "      ${YELLOW}expected:${NC} ${expect_note}"
        echo "[verify] FAIL: $desc dest=$dest got=$class($out_dev) expected=$expected args=${args[*]}" >> "${LOG_FILE:-/dev/null}"
    else
        echo "[verify] OK:   $desc dest=$dest via=$class($out_dev)" >> "${LOG_FILE:-/dev/null}"
    fi
}

# ICMP reachability (best-effort; many networks filter ping).
# Args: description  host  [bind_iface]
verify_one_ping() {
    local desc="$1" host="$2" iface="${3:-}"
    local ok_icon color args=(-c 1 -W 2)
    [ -n "$iface" ] && args+=(-I "$iface")

    if ping "${args[@]}" "$host" >/dev/null 2>&1; then
        ok_icon="✔"; color="${GREEN}"; verify_record 1
        ui_echo "   ${color}${ok_icon}${NC} ${BOLD}${desc}${NC}"
        ui_echo "      ${DIM}ping ${host}${NC}  →  reachable"
        echo "[verify] OK:   ping $host iface=${iface:-default}" >> "${LOG_FILE:-/dev/null}"
    else
        ok_icon="⚠"; color="${YELLOW}"
        # Do not fail the suite — ICMP is often filtered.
        ui_echo "   ${color}${ok_icon}${NC} ${BOLD}${desc}${NC}"
        ui_echo "      ${DIM}ping ${host}${NC}  →  no reply (ICMP may be filtered; not counted as fail)"
        echo "[verify] WARN: ping $host no reply (ignored)" >> "${LOG_FILE:-/dev/null}"
    fi
}

# DNS query via dig/nslookup/getent.
# Args: description  server_ip  [bind_hint: wan|wg0|any]
verify_one_dns() {
    local desc="$1" server="$2" bind="${3:-any}"
    local ok=0 ans="" ok_icon color

    if [ -z "$server" ]; then
        return 0
    fi

    if command -v dig >/dev/null 2>&1; then
        ans=$(dig +time=2 +tries=1 +short @"$server" example.com A 2>/dev/null | awk '/^[0-9]+\./{print; exit}')
        [ -n "$ans" ] && ok=1
    elif command -v nslookup >/dev/null 2>&1; then
        ans=$(nslookup example.com "$server" 2>/dev/null | awk '/^Address: /{a=$2} END{print a}')
        echo "$ans" | grep -Eq '^[0-9]+\.' && ok=1
    else
        # Last resort: only proves local resolver works, not $server.
        getent hosts example.com >/dev/null 2>&1 && ok=1 && ans="(via local resolver)"
    fi

    # For tunnel-exit servers, also confirm FIB would send them via wg0 when
    # bound (dnsmasq uses @wg0). Under Pi-bypass, Pi-local dig uses WAN — note it.
    local route_note=""
    if [ "$bind" = "wg0" ]; then
        local rdev
        rdev=$(verify_route_dev "$server")
        if [ "$rdev" = "wg0" ]; then
            route_note="route→wg0"
        else
            route_note="Pi route→${rdev:-?} (dnsmasq still uses @wg0 bind)"
        fi
    fi

    if [ "$ok" = "1" ]; then
        ok_icon="✔"; color="${GREEN}"; verify_record 1
        ui_echo "   ${color}${ok_icon}${NC} ${BOLD}${desc}${NC}"
        ui_echo "      ${DIM}dns @${server}${NC}  →  ${ans}${route_note:+ · $route_note}"
        echo "[verify] OK:   dns @$server -> $ans" >> "${LOG_FILE:-/dev/null}"
    else
        ok_icon="✖"; color="${RED}"; verify_record 0
        ui_echo "   ${color}${ok_icon}${NC} ${BOLD}${desc}${NC}"
        ui_echo "      ${DIM}dns @${server}${NC}  →  no answer"
        echo "[verify] FAIL: dns @$server" >> "${LOG_FILE:-/dev/null}"
    fi
}

verify_dns_section() {
    ui_echo ""
    ui_echo "   ${BOLD}DNS reachability${NC}"
    ui_echo ""

    local s
    if [ -n "${PI_DNS_SERVERS:-}" ]; then
        for s in $PI_DNS_SERVERS; do
            verify_one_dns "Pi DNS ($s via WAN)" "$s" "wan"
        done
    else
        ui_echo "   ${DIM}○ Pi DNS: not configured (PI_DNS_SERVERS empty)${NC}"
    fi

    case "${HOME_DNS_MODE:-skip}" in
        custom)
            for s in ${HOME_DNS_SERVERS:-}; do
                verify_one_dns "LAN DNS upstream ($s)" "$s" "wg0"
            done
            ;;
        tunnel)
            for s in ${HOME_DNS_TUNNEL_DEFAULTS:-1.1.1.1 8.8.8.8}; do
                verify_one_dns "LAN tunnel-exit DNS ($s @wg0)" "$s" "wg0"
            done
            ;;
        *)
            ui_echo "   ${DIM}○ LAN DNS: skip mode (uses Pi WAN resolvers)${NC}"
            ;;
    esac
}

verify_public_ip_section() {
    ui_echo ""
    ui_echo "   ${BOLD}Public IP comparison${NC}"
    ui_echo "   ${DIM}WAN = site ISP · Tunnel = home egress via wg0 · Endpoint = home WG peer address${NC}"
    ui_echo ""

    local wan_ip tun_ip ep_host ep_ip
    wan_ip=$(verify_public_ip_via "${WAN_IFACE:-}")
    if ip link show wg0 >/dev/null 2>&1; then
        tun_ip=$(verify_public_ip_via "wg0")
    else
        tun_ip=""
    fi
    ep_host=$(verify_extract_endpoint_host)
    ep_ip=$(verify_resolve_host "$ep_host")

    if [ -n "$wan_ip" ]; then
        verify_record 1
        ui_echo "   ${GREEN}✔${NC} ${BOLD}WAN egress${NC} (${WAN_IFACE:-wan})"
        ui_echo "      ${BOLD}${wan_ip}${NC}  ${DIM}(site / remote location)${NC}"
        echo "[verify] OK:   wan_ip=$wan_ip" >> "${LOG_FILE:-/dev/null}"
    else
        verify_record 0
        ui_echo "   ${RED}✖${NC} ${BOLD}WAN egress${NC} — could not fetch public IP"
        echo "[verify] FAIL: wan_ip empty" >> "${LOG_FILE:-/dev/null}"
    fi

    if [ -n "$tun_ip" ]; then
        verify_record 1
        ui_echo "   ${GREEN}✔${NC} ${BOLD}Tunnel egress${NC} (wg0)"
        ui_echo "      ${BOLD}${tun_ip}${NC}  ${DIM}(home / central peer NAT)${NC}"
        echo "[verify] OK:   tun_ip=$tun_ip" >> "${LOG_FILE:-/dev/null}"
    else
        verify_record 0
        ui_echo "   ${RED}✖${NC} ${BOLD}Tunnel egress${NC} — wg0 down or no public IP via tunnel"
        echo "[verify] FAIL: tun_ip empty" >> "${LOG_FILE:-/dev/null}"
    fi

    if [ -n "$ep_host" ]; then
        if [ -n "$ep_ip" ]; then
            verify_record 1
            ui_echo "   ${GREEN}✔${NC} ${BOLD}WG Endpoint${NC} ${DIM}${ep_host}${NC}"
            ui_echo "      resolves to ${BOLD}${ep_ip}${NC}"
            echo "[verify] OK:   endpoint $ep_host -> $ep_ip" >> "${LOG_FILE:-/dev/null}"
        else
            verify_record 0
            ui_echo "   ${RED}✖${NC} ${BOLD}WG Endpoint${NC} ${DIM}${ep_host}${NC} — DNS resolve failed"
            echo "[verify] FAIL: endpoint resolve $ep_host" >> "${LOG_FILE:-/dev/null}"
        fi
    else
        ui_echo "   ${DIM}○ WG Endpoint: not found in config${NC}"
    fi

    ui_echo ""
    # Interpret relationships (architecture-aware).
    if [ -n "$wan_ip" ] && [ -n "$tun_ip" ] && [ "$wan_ip" = "$tun_ip" ]; then
        verify_record 0
        ui_echo "   ${RED}✖${NC} ${BOLD}WAN and tunnel egress are the same (${wan_ip})${NC}"
        ui_echo "      ${DIM}Under Pi-bypass they should differ: tunnel should show home egress.${NC}"
        echo "[verify] FAIL: wan_ip == tun_ip ($wan_ip)" >> "${LOG_FILE:-/dev/null}"
    elif [ -n "$wan_ip" ] && [ -n "$tun_ip" ]; then
        verify_record 1
        ui_echo "   ${GREEN}✔${NC} ${BOLD}WAN ≠ tunnel egress${NC} — site vs home paths look distinct"
        echo "[verify] OK:   wan_ip != tun_ip" >> "${LOG_FILE:-/dev/null}"
    fi

    if [ -n "$tun_ip" ] && [ -n "$ep_ip" ]; then
        if [ "$tun_ip" = "$ep_ip" ]; then
            verify_record 1
            ui_echo "   ${GREEN}✔${NC} ${BOLD}Tunnel egress matches Endpoint IP${NC}"
            ui_echo "      ${DIM}Home peer likely NATs from the same address WireGuard listens on.${NC}"
            echo "[verify] OK:   tun_ip == endpoint_ip" >> "${LOG_FILE:-/dev/null}"
        else
            # Not necessarily a failure (CGNAT / different egress IP on home).
            ui_echo "   ${YELLOW}⚠${NC} ${BOLD}Tunnel egress (${tun_ip}) ≠ Endpoint (${ep_ip})${NC}"
            ui_echo "      ${DIM}OK if home NATs from a different address than the WG listen IP.${NC}"
            echo "[verify] WARN: tun_ip != endpoint_ip" >> "${LOG_FILE:-/dev/null}"
        fi
    fi

    if [ -n "$wan_ip" ] && [ -n "$ep_ip" ] && [ "$wan_ip" = "$ep_ip" ]; then
        ui_echo "   ${YELLOW}⚠${NC} ${BOLD}WAN egress equals Endpoint IP${NC}"
        ui_echo "      ${DIM}Unusual for a remote site (same public IP as home peer). Check topology.${NC}"
        echo "[verify] WARN: wan_ip == endpoint_ip" >> "${LOG_FILE:-/dev/null}"
    fi
}

# Main entry: print a readable report. Always returns 0 so setup is not aborted.
do_verify_routes() {
    VERIFY_PASS_COUNT=0
    VERIFY_FAIL_COUNT=0
    VERIFY_TOTAL_COUNT=0

    local box_w=76
    local content_w=72
    local border
    border=$(printf '─%.0s' $(seq 1 $((box_w - 2))))

    local mode="${LAN_FORWARD_MODE:-all}"
    local bypass="${PI_BYPASS_ROUTING:-false}"
    local client_ip home_host mode_label

    client_ip=$(verify_lan_client_ip)
    home_host=$(verify_first_home_host)

    if [ "$bypass" = "true" ] && [ "$mode" = "home" ]; then
        mode_label="home-only (LAN Internet via WAN; home CIDRs via VPN)"
    elif [ "$bypass" = "true" ]; then
        mode_label="all LAN traffic via VPN (kill-switch)"
    else
        mode_label="legacy (wg-quick routes; Pi may use tunnel too)"
    fi

    ui_echo ""
    ui_echo "${CYAN}╭${border}╮${NC}"
    ui_echo "${CYAN}│${NC} ${BOLD}${YELLOW}🧭 Route & reachability checks${NC}$(printf '%*s' $((content_w - 30)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}╰${border}╯${NC}"
    ui_echo ""
    ui_echo "   ${BOLD}Mode:${NC} ${mode_label}"
    ui_echo ""

    if [ "$bypass" != "true" ]; then
        ui_echo "   ${DIM}Pi-bypass is off — showing Pi-local lookups only.${NC}"
        ui_echo ""
        verify_one_route "Pi → Internet" "1.1.1.1" "wan"
        if [ -n "$home_host" ]; then
            local home_dev home_class home_expected="tunnel"
            home_dev=$(verify_route_dev "$home_host")
            home_class=$(verify_classify_dev "$home_dev")
            [ "$home_class" = "wan" ] && home_expected="wan"
            verify_one_route "Pi → home ($home_host)" "$home_host" "$home_expected"
        fi
    else
        if [ -z "${LAN_IFACE:-}" ]; then
            ui_echo "   ${YELLOW}⚠️${NC}  LAN_IFACE unset — cannot simulate LAN client traffic."
        else
            ui_echo "   ${BOLD}From a LAN client${NC} ${DIM}(${client_ip} on ${LAN_IFACE})${NC}"
            ui_echo "   ${DIM}Simulated with: ip route get <dest> from ${client_ip} iif ${LAN_IFACE}${NC}"
            ui_echo ""

            if [ -n "$home_host" ]; then
                verify_one_route "Home network ($home_host)" "$home_host" "tunnel" "$client_ip" "$LAN_IFACE"
            else
                ui_echo "   ${YELLOW}⚠️${NC}  No home subnet in AllowedIPs — skipped home route check."
                echo "[verify] SKIP home: no non-default AllowedIPs" >> "${LOG_FILE:-/dev/null}"
            fi

            local inet_expected="tunnel"
            [ "$mode" = "home" ] && inet_expected="wan"
            verify_one_route "Public Internet (1.1.1.1)" "1.1.1.1" "$inet_expected" "$client_ip" "$LAN_IFACE"
            verify_one_route "Public Internet (8.8.8.8)" "8.8.8.8" "$inet_expected" "$client_ip" "$LAN_IFACE"

            ui_echo ""
            ui_echo "   ${BOLD}From the Pi itself${NC} ${DIM}(no iif — Internet must stay on WAN)${NC}"
            ui_echo ""
            verify_one_route "Pi → Internet (1.1.1.1)" "1.1.1.1" "wan"
            if [ -n "$home_host" ]; then
                verify_one_route "Pi → home ($home_host)" "$home_host" "tunnel"
            fi
        fi
    fi

    # Live probes (best-effort).
    if [ -n "$home_host" ]; then
        ui_echo ""
        ui_echo "   ${BOLD}Reachability probes${NC}"
        ui_echo ""
        verify_one_ping "Ping home host via tunnel path" "$home_host" "wg0"
        verify_one_ping "Ping Internet via WAN" "1.1.1.1" "${WAN_IFACE:-}"
    fi

    verify_dns_section
    verify_public_ip_section

    ui_echo ""
    if [ "$VERIFY_FAIL_COUNT" -eq 0 ] && [ "$VERIFY_TOTAL_COUNT" -gt 0 ]; then
        ui_echo "   ${GREEN}${BOLD}Summary: ${VERIFY_PASS_COUNT}/${VERIFY_TOTAL_COUNT} checks passed${NC}"
    elif [ "$VERIFY_TOTAL_COUNT" -eq 0 ]; then
        ui_echo "   ${YELLOW}Summary: no checks ran.${NC}"
    else
        ui_echo "   ${RED}${BOLD}Summary: ${VERIFY_FAIL_COUNT}/${VERIFY_TOTAL_COUNT} check(s) failed.${NC}"
        ui_echo "   ${DIM}See $LOG_FILE · re-run: sudo ./scripts/setup-vpn-gateway.sh --verify-routes${NC}"
    fi
    ui_echo ""

    VERIFY_SUMMARY="${VERIFY_PASS_COUNT}/${VERIFY_TOTAL_COUNT} ok"
    [ "$VERIFY_FAIL_COUNT" -gt 0 ] && VERIFY_SUMMARY="${VERIFY_PASS_COUNT}/${VERIFY_TOTAL_COUNT} (${VERIFY_FAIL_COUNT} failed)"
    return 0
}

# Standalone: sudo ./scripts/setup-vpn-gateway.sh --verify-routes
run_verify_routes_only() {
    load_config
    NONINTERACTIVE="${NONINTERACTIVE:-false}"
    init_log
    check_root
    PROGRESS_UI_FD=""

    if [ -z "${LAN_IFACE:-}" ] || [ -z "${WAN_IFACE:-}" ]; then
        echo -e "${RED}✖${NC} WAN_IFACE/LAN_IFACE not set. Run setup first ($CONFIG_FILE)."
        exit 1
    fi
    if [ -z "${LAN_GATEWAY:-}" ] && [ -n "${LAN_CIDR:-}" ]; then
        LAN_GATEWAY=$(echo "$LAN_CIDR" | sed 's/\.0\/24$/.1/')
    fi
    WG_CONF_DEST="${WG_CONF_DEST:-/etc/wireguard/wg0.conf}"
    if [ ! -f "$WG_CONF_DEST" ] && [ -n "${WG_CONF_PATH:-}" ]; then
        WG_CONF_SRC="$WG_CONF_PATH"
    fi

    echo ""
    echo -e "${BOLD}Route & reachability verification${NC}"
    echo -e "${DIM}Routing, DNS, and public IP / Endpoint comparison.${NC}"
    do_verify_routes
}
