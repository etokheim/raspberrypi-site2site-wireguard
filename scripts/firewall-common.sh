# Sourced firewall helpers shared by setup and cleanup. No eval of rule text.
ensure_lan_egress_guard() {
    # Table-200 routes disappear with wg0; prevent fallthrough to WAN, including
    # established flows. Deliberately independent of wg-quick PostDown.
    iptables -N VPN_GW_EGRESS 2>/dev/null || true
    if [ "${PI_BYPASS_ROUTING:-false}" = true ]; then
        case "${LAN_FORWARD_MODE:-all}" in
            all)
                # Replace the sole owned rule atomically on interface changes;
                # never flush an active full-tunnel guard before its replacement.
                if ! iptables -C VPN_GW_EGRESS -i "$LAN_IFACE" ! -o wg0 -j REJECT >/dev/null 2>&1; then
                    iptables -R VPN_GW_EGRESS 1 -i "$LAN_IFACE" ! -o wg0 -j REJECT >> "$LOG_FILE" 2>&1 ||
                        iptables -A VPN_GW_EGRESS -i "$LAN_IFACE" ! -o wg0 -j REJECT >> "$LOG_FILE" 2>&1 || return 1
                fi
                ;;
            home) iptables -F VPN_GW_EGRESS >> "$LOG_FILE" 2>&1 || return 1 ;;
            *) echo 'Invalid LAN_FORWARD_MODE (expected all or home)' >&2; return 1 ;;
        esac
    else
        iptables -F VPN_GW_EGRESS >> "$LOG_FILE" 2>&1 || return 1
    fi
    iptables -C FORWARD -j VPN_GW_EGRESS >/dev/null 2>&1 ||
        iptables -I FORWARD 1 -j VPN_GW_EGRESS >> "$LOG_FILE" 2>&1
}

remove_lan_egress_guard() {
    while iptables -D FORWARD -j VPN_GW_EGRESS 2>/dev/null; do :; done
    iptables -F VPN_GW_EGRESS 2>/dev/null || true
    iptables -X VPN_GW_EGRESS 2>/dev/null || true
}

remove_gateway_input_rules() {
    local tag="$1" saved numbers number
    [ -n "$tag" ] || return 1
    # Legacy NAT setup and standalone cleanup also use this helper. Do not fall
    # back to whitespace matching if Python is absent (or install from cleanup).
    command -v python3 >/dev/null 2>&1 || {
        echo 'Firewall ownership parsing needs python3. Install it first: sudo apt-get install python3' >&2
        return 1
    }
    saved=$(iptables -S INPUT 2>>"$LOG_FILE") || return 1
    # Decode complete arguments, never execute rule text. Embedded --comment
    # text is data, not another option. Parse the ENTIRE listing before emitting
    # numbers so a later malformed rule cannot cause partial deletion.
    # Descending numbers avoid reserializing rules and renumbering next targets.
    numbers=$(printf '%s\n' "$saved" | python3 -c '
import shlex
import sys

tag = sys.argv[1]
owned = []
number = 0
try:
    for line in sys.stdin:
        # -S emits one rule per line, not shell backslash-newline continuations.
        args = shlex.split(line.rstrip("\n"), comments=False, posix=True)
        if not args:
            continue
        if args[:2] == ["-P", "INPUT"] and len(args) == 3:
            continue
        if args[:2] != ["-A", "INPUT"] or len(args) < 3:
            raise ValueError("unexpected INPUT listing")
        number += 1
        comments = []
        i = 2
        while i < len(args):
            if args[i] == "--comment":
                if i + 1 == len(args):
                    raise ValueError("missing comment argument")
                comments.append(args[i + 1])
                i += 2
            else:
                i += 1
        if len(comments) > 1:
            raise ValueError("ambiguous comment options")
        if comments == [tag]:
            owned.append(number)
except ValueError as exc:
    print("Refusing firewall deletion: " + str(exc), file=sys.stderr)
    sys.exit(1)
for number in reversed(owned):
    print(number)
' "$tag") || return 1
    while IFS= read -r number; do
        [ -n "$number" ] || continue
        iptables -D INPUT "$number" >> "$LOG_FILE" 2>&1 || return 1
    done <<< "$numbers"
}
