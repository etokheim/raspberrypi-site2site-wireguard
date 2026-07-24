# speedtest-comparison.sh
# Sourced by setup-vpn-gateway.sh. Compares Ookla speedtests on WAN vs wg0
# with a live TTY panel. Also reachable via: setup-vpn-gateway.sh --speedtest
#
# Expects (from the parent script): ui_echo, ui_printf, LOG_FILE, color vars,
# WAN_IFACE, load_config, check_root, init_log (optional).

# --- Ookla CLI presence / install ------------------------------------------------

is_ookla_speedtest() {
    command -v speedtest >/dev/null 2>&1 || return 1
    # Official binary prints "Speedtest by Ookla"; refuse the python speedtest-cli.
    speedtest --version 2>&1 | grep -qi 'Ookla'
}

ensure_ookla_speedtest() {
    if is_ookla_speedtest; then
        echo "[speedtest] Ookla CLI already installed: $(command -v speedtest)" >> "${LOG_FILE:-/dev/null}"
        return 0
    fi

    echo "[speedtest] Installing Ookla Speedtest CLI..." >> "${LOG_FILE:-/dev/null}"

    # Conflicting packages from Debian/PyPI take the `speedtest` name.
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y speedtest-cli speedtest 2>>"${LOG_FILE:-/dev/null}" || true
        if ! command -v curl >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confold' curl \
                >>"${LOG_FILE:-/dev/null}" 2>&1 || true
        fi
        if ! command -v python3 >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confold' python3 \
                >>"${LOG_FILE:-/dev/null}" 2>&1 || true
        fi
        # Official Ookla apt repo (armhf / arm64 / amd64).
        if curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh \
            | bash >>"${LOG_FILE:-/dev/null}" 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confold' speedtest \
                >>"${LOG_FILE:-/dev/null}" 2>&1 || true
        fi
    fi

    if ! is_ookla_speedtest; then
        echo "[speedtest] ERROR: Ookla CLI install failed" >> "${LOG_FILE:-/dev/null}"
        return 1
    fi
    return 0
}

# --- Live panel state ------------------------------------------------------------

SPEEDTEST_BOX_LINES=0
ST_WAN_DL="—"
ST_WAN_UL="—"
ST_WAN_PING="—"
ST_WAN_PROG_DL=0
ST_WAN_PROG_UL=0
ST_WG_DL="—"
ST_WG_UL="—"
ST_WG_PING="—"
ST_WG_PROG_DL=0
ST_WG_PROG_UL=0
ST_WAN_IP="…"
ST_WG_IP="…"
ST_WAN_ISP=""
ST_WG_ISP=""
ST_ACTIVE="idle"   # wan-download|wan-upload|tunnel-download|tunnel-upload|done
ST_STATUS_LINE=""

speedtest_reset_state() {
    SPEEDTEST_BOX_LINES=0
    ST_WAN_DL="—"; ST_WAN_UL="—"; ST_WAN_PING="—"
    ST_WAN_PROG_DL=0; ST_WAN_PROG_UL=0
    ST_WG_DL="—"; ST_WG_UL="—"; ST_WG_PING="—"
    ST_WG_PROG_DL=0; ST_WG_PROG_UL=0
    ST_WAN_IP="…"; ST_WG_IP="…"
    ST_WAN_ISP=""; ST_WG_ISP=""
    ST_ACTIVE="idle"
    ST_STATUS_LINE="Preparing…"
}

# $1 = fraction 0.0–1.0 (or percent 0–100), $2 = width
speedtest_bar() {
    local frac="$1"
    local width="${2:-22}"
    local pct filled empty i bar=""
    pct=$(awk -v f="$frac" 'BEGIN {
        if (f+0 > 1) f = f/100.0
        if (f < 0) f = 0
        if (f > 1) f = 1
        printf "%d", f*100
    }')
    filled=$((pct * width / 100))
    empty=$((width - filled))
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    printf '%s' "$bar"
}

speedtest_pad() {
    local text="$1"
    local width="$2"
    # Strip ANSI for length
    local plain
    plain=$(printf '%s' "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#plain}
    if [ "$len" -ge "$width" ]; then
        printf '%s' "$text"
        return
    fi
    printf '%s%*s' "$text" $((width - len)) ''
}

speedtest_draw_panel() {
    local box_w=76
    local content_w=72
    local border
    border=$(printf '─%.0s' $(seq 1 $((box_w - 2))))

    if [ "${SPEEDTEST_BOX_LINES:-0}" -gt 0 ]; then
        local j
        for ((j=0; j<SPEEDTEST_BOX_LINES; j++)); do
            ui_printf "\033[A\033[2K"
        done
    fi

    local lines=0
    local wan_mark="" wg_mark=""
    case "$ST_ACTIVE" in
        wan-*)     wan_mark="${YELLOW}▶${NC}" ;;
        tunnel-*)  wg_mark="${YELLOW}▶${NC}" ;;
        done)      wan_mark="${GREEN}✔${NC}"; wg_mark="${GREEN}✔${NC}" ;;
        *)         wan_mark=" "; wg_mark=" " ;;
    esac

    ui_echo "${CYAN}╭${border}╮${NC}"
    ui_echo "${CYAN}│${NC} ${BOLD}${YELLOW}⚡ Speedtest comparison${NC}$(printf '%*s' $((content_w - 24)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}├${border}┤${NC}"
    lines=$((lines + 3))

    local wan_label wg_label
    wan_label=$(speedtest_pad "Direct Internet (${WAN_IFACE:-wan})" 40)
    wg_label=$(speedtest_pad "WireGuard tunnel (wg0)" 40)

    ui_echo "${CYAN}│${NC} ${wan_mark} ${BOLD}${wan_label}${NC}$(printf '%*s' $((content_w - 43)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}↓${NC} Download  $(speedtest_bar "$ST_WAN_PROG_DL")  ${BOLD}$(printf '%7s' "$ST_WAN_DL")${NC} Mbps$(printf '%*s' $((content_w - 48)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}↑${NC} Upload    $(speedtest_bar "$ST_WAN_PROG_UL")  ${BOLD}$(printf '%7s' "$ST_WAN_UL")${NC} Mbps$(printf '%*s' $((content_w - 48)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}⟳${NC} Ping      $(printf '%7s' "$ST_WAN_PING") ms$(printf '%*s' $((content_w - 24)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}IP${NC}         $(speedtest_pad "${ST_WAN_IP}" 40)$(printf '%*s' $((content_w - 51)) '') ${CYAN}│${NC}"
    lines=$((lines + 5))

    ui_echo "${CYAN}│${NC}$(printf '%*s' "$content_w" '') ${CYAN}│${NC}"
    lines=$((lines + 1))

    ui_echo "${CYAN}│${NC} ${wg_mark} ${BOLD}${wg_label}${NC}$(printf '%*s' $((content_w - 43)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}↓${NC} Download  $(speedtest_bar "$ST_WG_PROG_DL")  ${BOLD}$(printf '%7s' "$ST_WG_DL")${NC} Mbps$(printf '%*s' $((content_w - 48)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}↑${NC} Upload    $(speedtest_bar "$ST_WG_PROG_UL")  ${BOLD}$(printf '%7s' "$ST_WG_UL")${NC} Mbps$(printf '%*s' $((content_w - 48)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}⟳${NC} Ping      $(printf '%7s' "$ST_WG_PING") ms$(printf '%*s' $((content_w - 24)) '') ${CYAN}│${NC}"
    ui_echo "${CYAN}│${NC}   ${DIM}IP${NC}         $(speedtest_pad "${ST_WG_IP}" 40)$(printf '%*s' $((content_w - 51)) '') ${CYAN}│${NC}"
    lines=$((lines + 5))

    ui_echo "${CYAN}├${border}┤${NC}"
    ui_echo "${CYAN}│${NC} ${DIM}$(speedtest_pad "${ST_STATUS_LINE}" "$content_w")${NC} ${CYAN}│${NC}"
    ui_echo "${CYAN}╰${border}╯${NC}"
    lines=$((lines + 3))

    SPEEDTEST_BOX_LINES=$lines
}

# Parse one Ookla JSONL line → sets PARSE_KIND and related PARSE_* vars.
# Prefer python3; fall back to sed for bandwidth-only progress.
speedtest_parse_jsonl_line() {
    local line="$1"
    PARSE_KIND=""
    PARSE_MBPS=""
    PARSE_PROGRESS=""
    PARSE_PING=""
    PARSE_DL=""
    PARSE_UL=""
    PARSE_ISP=""
    PARSE_URL=""

    if command -v python3 >/dev/null 2>&1; then
        local out
        out=$(python3 -c '
import json, sys
try:
    o = json.loads(sys.argv[1])
except Exception:
    sys.exit(0)

def mbps(b):
    try:
        return "{:.1f}".format((float(b) * 8) / 1000000.0)
    except Exception:
        return ""

t = o.get("type") or ""
if t == "ping":
    lat = (o.get("ping") or {}).get("latency")
    print("ping\t{}".format(lat if lat is not None else ""))
elif t == "download":
    d = o.get("download") or {}
    print("download\t{}\t{}".format(mbps(d.get("bandwidth")), d.get("progress") or 0))
elif t == "upload":
    u = o.get("upload") or {}
    print("upload\t{}\t{}".format(mbps(u.get("bandwidth")), u.get("progress") or 0))
elif t == "result":
    d = o.get("download") or {}
    u = o.get("upload") or {}
    p = o.get("ping") or {}
    isp = (o.get("isp") or "").replace("\t", " ")
    url = ((o.get("result") or {}).get("url") or "")
    print("result\t{}\t{}\t{}\t{}\t{}".format(
        mbps(d.get("bandwidth")), mbps(u.get("bandwidth")),
        p.get("latency") or "", isp, url))
' "$line" 2>/dev/null || true)
        [ -z "$out" ] && return 0
        PARSE_KIND=$(printf '%s\n' "$out" | cut -f1)
        case "$PARSE_KIND" in
            ping)
                PARSE_PING=$(printf '%s\n' "$out" | cut -f2)
                ;;
            download|upload)
                PARSE_MBPS=$(printf '%s\n' "$out" | cut -f2)
                PARSE_PROGRESS=$(printf '%s\n' "$out" | cut -f3)
                ;;
            result)
                PARSE_DL=$(printf '%s\n' "$out" | cut -f2)
                PARSE_UL=$(printf '%s\n' "$out" | cut -f3)
                PARSE_PING=$(printf '%s\n' "$out" | cut -f4)
                PARSE_ISP=$(printf '%s\n' "$out" | cut -f5)
                PARSE_URL=$(printf '%s\n' "$out" | cut -f6)
                ;;
        esac
        return 0
    fi

    # sed fallback (no python3)
    if echo "$line" | grep -q '"type":"download"'; then
        PARSE_KIND="download"
        PARSE_MBPS=$(echo "$line" | sed -n 's/.*"bandwidth":\([0-9][0-9]*\).*/\1/p' | head -1 \
            | awk '{printf "%.1f", $1*8/1000000}')
        PARSE_PROGRESS=$(echo "$line" | sed -n 's/.*"progress":\([0-9.]*\).*/\1/p' | head -1)
    elif echo "$line" | grep -q '"type":"upload"'; then
        PARSE_KIND="upload"
        PARSE_MBPS=$(echo "$line" | sed -n 's/.*"bandwidth":\([0-9][0-9]*\).*/\1/p' | head -1 \
            | awk '{printf "%.1f", $1*8/1000000}')
        PARSE_PROGRESS=$(echo "$line" | sed -n 's/.*"progress":\([0-9.]*\).*/\1/p' | head -1)
    elif echo "$line" | grep -q '"type":"ping"'; then
        PARSE_KIND="ping"
        PARSE_PING=$(echo "$line" | sed -n 's/.*"latency":\([0-9.]*\).*/\1/p' | head -1)
    elif echo "$line" | grep -q '"type":"result"'; then
        PARSE_KIND="result"
        # Best-effort: first bandwidth ≈ download, second ≈ upload
        local bws
        bws=$(echo "$line" | grep -o '"bandwidth":[0-9]*' | cut -d: -f2)
        PARSE_DL=$(echo "$bws" | sed -n '1p' | awk '{printf "%.1f", $1*8/1000000}')
        PARSE_UL=$(echo "$bws" | sed -n '2p' | awk '{printf "%.1f", $1*8/1000000}')
        PARSE_PING=$(echo "$line" | sed -n 's/.*"latency":\([0-9.]*\).*/\1/p' | head -1)
    fi
}

speedtest_apply_parse() {
    local side="$1"  # wan|tunnel
    case "$PARSE_KIND" in
        ping)
            local ping_fmt
            ping_fmt=$(awk -v p="$PARSE_PING" 'BEGIN { if (p=="") print "—"; else printf "%.0f", p+0 }')
            if [ "$side" = "wan" ]; then ST_WAN_PING="$ping_fmt"; else ST_WG_PING="$ping_fmt"; fi
            ;;
        download)
            if [ "$side" = "wan" ]; then
                ST_ACTIVE="wan-download"
                ST_WAN_DL="${PARSE_MBPS:-$ST_WAN_DL}"
                ST_WAN_PROG_DL="${PARSE_PROGRESS:-$ST_WAN_PROG_DL}"
            else
                ST_ACTIVE="tunnel-download"
                ST_WG_DL="${PARSE_MBPS:-$ST_WG_DL}"
                ST_WG_PROG_DL="${PARSE_PROGRESS:-$ST_WG_PROG_DL}"
            fi
            ;;
        upload)
            if [ "$side" = "wan" ]; then
                ST_ACTIVE="wan-upload"
                ST_WAN_UL="${PARSE_MBPS:-$ST_WAN_UL}"
                ST_WAN_PROG_UL="${PARSE_PROGRESS:-$ST_WAN_PROG_UL}"
                ST_WAN_PROG_DL=1
            else
                ST_ACTIVE="tunnel-upload"
                ST_WG_UL="${PARSE_MBPS:-$ST_WG_UL}"
                ST_WG_PROG_UL="${PARSE_PROGRESS:-$ST_WG_PROG_UL}"
                ST_WG_PROG_DL=1
            fi
            ;;
        result)
            if [ "$side" = "wan" ]; then
                ST_WAN_DL="${PARSE_DL:-$ST_WAN_DL}"
                ST_WAN_UL="${PARSE_UL:-$ST_WAN_UL}"
                ST_WAN_PROG_DL=1
                ST_WAN_PROG_UL=1
                if [ -n "$PARSE_PING" ]; then
                    ST_WAN_PING=$(awk -v p="$PARSE_PING" 'BEGIN { printf "%.0f", p+0 }')
                fi
                ST_WAN_ISP="$PARSE_ISP"
            else
                ST_WG_DL="${PARSE_DL:-$ST_WG_DL}"
                ST_WG_UL="${PARSE_UL:-$ST_WG_UL}"
                ST_WG_PROG_DL=1
                ST_WG_PROG_UL=1
                if [ -n "$PARSE_PING" ]; then
                    ST_WG_PING=$(awk -v p="$PARSE_PING" 'BEGIN { printf "%.0f", p+0 }')
                fi
                ST_WG_ISP="$PARSE_ISP"
            fi
            ;;
    esac
}

speedtest_fetch_public_ip() {
    local iface="${1:-}"
    local ip=""
    if [ -n "$iface" ]; then
        ip=$(curl -4 -s --max-time 8 --interface "$iface" https://api.ipify.org 2>/dev/null || true)
    else
        ip=$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null || true)
    fi
    if [ -z "$ip" ]; then
        echo "?"
    else
        echo "$ip"
    fi
}

speedtest_run_one() {
    local side="$1"   # wan|tunnel
    local iface="$2"  # eth0|wg0
    local label="$3"
    local line

    ST_STATUS_LINE="Running Ookla on ${label} (${iface})…"
    if [ "$side" = "wan" ]; then ST_ACTIVE="wan-download"; else ST_ACTIVE="tunnel-download"; fi
    speedtest_draw_panel

    # Accept license non-interactively; JSONL streams progress + final result.
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        echo "[speedtest:$side] $line" >> "${LOG_FILE:-/dev/null}"
        speedtest_parse_jsonl_line "$line"
        [ -z "$PARSE_KIND" ] && continue
        speedtest_apply_parse "$side"
        speedtest_draw_panel
    done < <(speedtest --accept-license --accept-gdpr --format=jsonl --progress=yes \
                --interface="$iface" 2>>"${LOG_FILE:-/dev/null}" || true)

    # Ensure bars complete even if result line was missed
    if [ "$side" = "wan" ]; then
        ST_WAN_PROG_DL=1
        ST_WAN_PROG_UL=1
    else
        ST_WG_PROG_DL=1
        ST_WG_PROG_UL=1
    fi
}

speedtest_delta_pct() {
    local a="$1" b="$2"
    awk -v a="$a" -v b="$b" 'BEGIN {
        if (a+0 == 0 || a == "—" || b == "—") { print "—"; exit }
        printf "%+.0f%%", ((b+0)-(a+0))*100.0/(a+0)
    }'
}

speedtest_delta_ms() {
    local a="$1" b="$2"
    awk -v a="$a" -v b="$b" 'BEGIN {
        if (a == "—" || b == "—") { print "—"; exit }
        printf "%+.0f ms", (b+0)-(a+0)
    }'
}

speedtest_print_summary() {
    local dl_d ul_d ping_d
    dl_d=$(speedtest_delta_pct "$ST_WAN_DL" "$ST_WG_DL")
    ul_d=$(speedtest_delta_pct "$ST_WAN_UL" "$ST_WG_UL")
    ping_d=$(speedtest_delta_ms "$ST_WAN_PING" "$ST_WG_PING")

    ui_echo ""
    ui_echo "${BOLD}Results${NC}"
    ui_echo "  ${DIM}Metric          Direct (WAN)     Tunnel (wg0)     Delta${NC}"
    ui_echo "  Download        $(printf '%-16s' "${ST_WAN_DL} Mbps") $(printf '%-16s' "${ST_WG_DL} Mbps") ${dl_d}"
    ui_echo "  Upload          $(printf '%-16s' "${ST_WAN_UL} Mbps") $(printf '%-16s' "${ST_WG_UL} Mbps") ${ul_d}"
    ui_echo "  Idle latency    $(printf '%-16s' "${ST_WAN_PING} ms") $(printf '%-16s' "${ST_WG_PING} ms") ${ping_d}"
    ui_echo "  Public IP       $(printf '%-16s' "$ST_WAN_IP") $(printf '%-16s' "$ST_WG_IP")"
    if [ -n "$ST_WAN_ISP" ] || [ -n "$ST_WG_ISP" ]; then
        ui_echo "  ISP             $(printf '%-16s' "${ST_WAN_ISP:---}") $(printf '%-16s' "${ST_WG_ISP:---}")"
    fi
    ui_echo ""
    ui_echo "  ${DIM}Under Pi-bypass, Direct = site ISP; Tunnel = home/peer egress (NAT).${NC}"
    ui_echo "  ${DIM}A lower tunnel score is normal (encryption + home uplink).${NC}"
}

speedtest_check_wg() {
    if ! ip link show wg0 >/dev/null 2>&1; then
        return 1
    fi
    # Handshake within last 3 minutes is healthy; still allow test if interface exists.
    return 0
}

speedtest_wg_handshake_note() {
    local hs now age
    hs=$(wg show wg0 latest-handshakes 2>/dev/null | awk 'NR==1 {print $2}')
    now=$(date +%s)
    if [ -z "$hs" ] || [ "$hs" = "0" ]; then
        echo "no handshake yet"
        return
    fi
    age=$((now - hs))
    if [ "$age" -lt 180 ]; then
        echo "handshake ${age}s ago (ok)"
    else
        echo "handshake ${age}s ago (stale?)"
    fi
}

# Main comparison entry used by setup (last step) and --speedtest.
# Returns 0 even on partial failure so setup is not aborted; prints warnings.
do_speedtest_comparison() {
    local wan_iface="${WAN_IFACE:-}"
    if [ -z "$wan_iface" ]; then
        # Best-effort: default route iface
        wan_iface=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    fi
    if [ -z "$wan_iface" ]; then
        ui_echo "${YELLOW}⚠️${NC}  Speedtest skipped: could not determine WAN interface."
        return 0
    fi
    WAN_IFACE="$wan_iface"

    speedtest_reset_state
    ST_STATUS_LINE="Checking Ookla CLI…"
    speedtest_draw_panel

    if ! ensure_ookla_speedtest; then
        ST_STATUS_LINE="Ookla CLI install failed — see log"
        speedtest_draw_panel
        ui_echo "${YELLOW}⚠️${NC}  Speedtest skipped (Ookla CLI not available). Log: ${LOG_FILE:-n/a}"
        return 0
    fi

    ST_STATUS_LINE="Fetching public IPs…"
    speedtest_draw_panel
    ST_WAN_IP=$(speedtest_fetch_public_ip "$WAN_IFACE")
    if speedtest_check_wg; then
        ST_WG_IP=$(speedtest_fetch_public_ip "wg0")
        ST_STATUS_LINE="wg0 up ($(speedtest_wg_handshake_note))"
    else
        ST_WG_IP="(wg0 down)"
        ST_STATUS_LINE="wg0 is down — tunnel test will be skipped"
    fi
    speedtest_draw_panel

    # 1) Direct Internet via WAN iface bind
    speedtest_run_one "wan" "$WAN_IFACE" "direct Internet"

    # 2) Through WireGuard (SO_BINDTODEVICE wg0) — required under Pi-bypass
    if speedtest_check_wg; then
        speedtest_run_one "tunnel" "wg0" "WireGuard tunnel"
    else
        ST_STATUS_LINE="Skipped tunnel test (wg0 down)"
        speedtest_draw_panel
    fi

    ST_ACTIVE="done"
    ST_STATUS_LINE="Done"
    speedtest_draw_panel
    speedtest_print_summary

    # Persist a one-line summary into the setup log
    {
        echo "[speedtest] WAN  dl=${ST_WAN_DL} ul=${ST_WAN_UL} ping=${ST_WAN_PING} ip=${ST_WAN_IP} isp=${ST_WAN_ISP}"
        echo "[speedtest] WG0  dl=${ST_WG_DL} ul=${ST_WG_UL} ping=${ST_WG_PING} ip=${ST_WG_IP} isp=${ST_WG_ISP}"
    } >> "${LOG_FILE:-/dev/null}"

    return 0
}

# Standalone entry: sudo ./scripts/setup-vpn-gateway.sh --speedtest
run_speedtest_only() {
    load_config
    NONINTERACTIVE="${NONINTERACTIVE:-false}"
    init_log
    check_root
    # Keep UI on stdout (no become_unattended) so the live panel is visible.
    PROGRESS_UI_FD=""

    if [ -z "${WAN_IFACE:-}" ]; then
        echo -e "${RED}✖${NC} WAN_IFACE not set. Run setup first or set it in $CONFIG_FILE"
        exit 1
    fi

    echo ""
    echo -e "${BOLD}WAN vs WireGuard speedtest${NC}"
    echo -e "${DIM}Direct bind: ${WAN_IFACE}  ·  Tunnel bind: wg0${NC}"
    echo ""

    if ! speedtest_check_wg; then
        echo -e "${YELLOW}⚠️${NC}  wg0 is not up. Start the gateway first:"
        echo "     sudo ./gateway-manage-or-setup.sh --start"
        echo ""
        echo -ne "   Continue with WAN-only test? [y/N]: "
        read -r ans < /dev/tty
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    do_speedtest_comparison
}
