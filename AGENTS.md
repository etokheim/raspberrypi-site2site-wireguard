# AI Harness Instructions

This file captures durable, non-obvious decisions for AI agents working in this repository.

## Core Principle: Unattended Setup

For setup or reconfiguration flows, use a two-phase approach:

1. **Planning/Input phase**  
   Collect all required user answers first (interfaces, LAN CIDR, WireGuard config path, firewall choice, optional features, etc.).
2. **Execution phase**  
   Only after inputs are complete, run long or disruptive actions (installing packages, changing system config, restarting services).

Do not start dependency installation early while still asking configuration questions.

## Why This Matters

- Package install and network changes can take significant time.
- The user should be able to answer prompts once and then leave the process unattended.
- Mid-install prompts increase failure risk and operator frustration on remote systems.

## Agent Behavior Requirements

- Prefer "gather once, execute once" for interactive setup UX.
- If information is missing, ask before triggering long-running operations.
- Keep setup steps idempotent and resilient across reboot/power loss.

### Interactive prompt layout

Every setup question must follow **question → dim helper → short input cue**:

1. Blank line (separates from the previous answer)
2. Bold question headline
3. Dim helper lines that clarify *this* question only
4. Short cue last (`[Y/n]:`, `IP:`, `Path:`, …)

Never put helper text before the question or after the input cue. Use the
shared `prompt_q` / `prompt_h` / `prompt_cue` helpers in
`scripts/setup-vpn-gateway.sh` (set `PROMPT_FD=2` when stdout is captured).

### Selective edit (change one setting)

Prefer `gateway-manage-or-setup.sh` → Edit → **Change one setting** (or
`setup-vpn-gateway.sh --edit`) when the operator only wants to tweak one
value. That path must **reapply only the subsystems that setting touches**
(e.g. LAN forward mode → rewrite wg0 PostUp + reload wg + verify; HOME_DNS
→ dnsmasq only). Do not force a full stack rebuild for a single-setting edit.

**Apply saved configuration** (`--apply` / Edit menu option 3) must stay
supported: re-apply `vpn-gateway.conf` with no prompts (hand-edits and
idempotent repair). Full reconfigure remains for green-field or multi-setting
prompt walkthroughs.
## Critical Operational Principles

These principles must be preserved by any change to setup/cleanup/management scripts:

### SSH-Safety During Install

Remote installation over SSH must remain possible. Avoid actions that can drop the operator's SSH connection:

- Never unconditionally `ip addr flush` an interface without first verifying it is not the SSH-bearing path.
- Detect the SSH-bearing interface (via `SSH_CONNECTION` / `who am i`) and warn loudly before reassigning its address.
- Prefer to skip a step when the desired state already matches current state (idempotent no-op).
- When changing iptables, ensure ACCEPT rules for SSH precede any DROP/REJECT rules at all times.

### Reboot Survivability

Configuration must survive reboot and power loss without manual intervention:

- Persist all iptables/nat rules to disk after applying them, regardless of optional features.
- Do not couple non-tunnel-related rules (like WAN MASQUERADE) to `wg-quick` PostUp/PostDown.
- Use systemd ordering (`After`, `Wants`, optional `BindsTo`) to make services start only when their network prerequisites are ready.
- Back up replaced system files only the first time (do not overwrite the backup on re-runs).

### Re-Run Idempotency

Re-running setup on a configured Pi must reconfigure cleanly and fix prior reboot/persistence issues:

- Detect existing systemd units, drop-ins, and config files; replace only when content differs.
- Clean up rules and units tied to a previous interface when the user reassigns interfaces.
- Avoid destructive restarts (e.g., `wg-quick down`) when nothing changed.
- The `--start` recovery path should also create/update missing systemd units, not just start them.

### Network Architecture: Forwarding Gateway, Not Full-Tunnel Client

This project configures the Pi as a site-to-site forwarding gateway. The
gateway's own outbound traffic must NEVER go through the VPN by default.
Pi-bypass routing (`Table = off` in `wg0.conf` + an `iif=$LAN_IFACE`
policy rule that points forwarded traffic at routing table 200) is the
recommended mode and the only mode that keeps remote management (SSH
over Internet, Pi Connect, apt) working when the user's `wg0.conf` has
`AllowedIPs = 0.0.0.0/0`.

- Forwarded packets (`iif=$LAN_IFACE`) -> table 200 -> (see LAN_FORWARD_MODE).
- Locally-generated packets (no `iif`) -> main table -> WAN.
- Per-peer subnets (non-default `AllowedIPs` entries) get explicit
  `dev wg0` routes in BOTH the main table (so the Pi reaches them) and
  table 200 (so LAN clients reach them via the tunnel).
- `LAN_FORWARD_MODE=all` (default): table 200 also has `default dev wg0`
  (full LAN tunnel). When `wg0` is down, LAN Internet fails (kill-switch);
  Pi-local traffic continues via WAN.
- `LAN_FORWARD_MODE=home`: table 200 has **only** home subnet routes.
  Other LAN Internet falls through to the main table (WAN). When `wg0`
  is down, only home access fails. Do not rewrite AllowedIPs for this;
  routing decides egress. Prefer `HOME_DNS_MODE=custom` over tunnel-exit.
- Ensure LAN→WAN FORWARD (+ WAN MASQUERADE) via `ensure_nat_rules` so
  home-only Internet egress works.
- After WireGuard is up, run `do_verify_routes` (progress step +
  `--verify-routes`): simulate LAN client lookups with
  `ip route get <dest> from <lan-client> iif $LAN_IFACE`, probe DNS
  reachability (PI_DNS / HOME_DNS), and compare public IPs (WAN egress vs
  tunnel egress vs WG Endpoint host). Do not fail setup on a failed check.
- Re-runs must remain conflict-free: flush table 200 / old `iif` rules before
  wg restart; remove tagged firewall rules when firewall is disabled; always
  allow changing `LAN_FORWARD_MODE` (and optionally other settings) when
  reusing `vpn-gateway.conf`.

Any change that re-introduces a default route via `wg0` in the main
routing table - or that ties non-tunnel-related rules to `wg-quick`
PostUp/PostDown - is a regression.

### Dual-DNS Plane (Pi-Bypass Mode)

When Pi-bypass routing is on, locally-generated DNS lookups from the Pi
no longer ride through the tunnel by default - they go via WAN like any
other Pi-local traffic. Without explicit DNS configuration, both the Pi
*and* (via dnsmasq's upstream lookups) the LAN clients leak DNS to the
WAN ISP, defeating GeoDNS / CDN routing.

The fix is two distinct DNS planes, controlled by three
`vpn-gateway.conf` variables:

- `HOME_DNS_MODE` (LAN client plane) - `tunnel` | `custom` |
  `skip`. Default depends on the WireGuard config (see priority below).
  - **`tunnel`**: dnsmasq config gets `no-resolv` plus
    `server=<ip>@wg0` for each entry in `HOME_DNS_TUNNEL_DEFAULTS`
    (currently `1.1.1.1 8.8.8.8`). The `@wg0` source-interface binding
    forces dnsmasq to send the upstream lookup out via wg0; the home
    peer NATs the lookup. Works without any DNS server inside the home
    network. Requires `AllowedIPs` to cover the chosen public DNS IPs
    (typically via `0.0.0.0/0`).
  - **`custom`**: dnsmasq config gets `no-resolv` plus
    `server=<ip>` for each entry in `HOME_DNS_SERVERS`. Routes via wg0
    implicitly because the destination is inside an `AllowedIPs`
    subnet. Use this if you run a real home DNS server (Pi-hole,
    AdGuard Home, your home router's resolver) and want LAN clients
    to pick up local hostname resolution.
  - **`skip`**: no `no-resolv`, no `server=`. dnsmasq uses the Pi's
    `/etc/resolv.conf` upstream -> public DNS via WAN -> geo-leak.
- `HOME_DNS_SERVERS` (custom-mode IPs only) - space-separated IPv4/IPv6.
  **Default priority** when forwarding LAN DNS through the tunnel:
  1. WireGuard `DNS =` from the source config → `MODE=custom` (operator
     already named a home resolver; confirm-or-override prompt).
  2. Else if `LAN_FORWARD_MODE=home` → prefer `MODE=custom` (home `.1`
     / ask). Do **not** auto-default to tunnel-exit in home-only mode
     (DNS via home while Internet via WAN is usually confusing).
  3. Else if `AllowedIPs` has a default route → `MODE=tunnel`.
  4. Else `.1` of the first home subnet → `MODE=custom`.
  `DNS =` itself is still *not* applied to the Pi under Pi-bypass (stripped
  from the installed `wg0.conf`); we only reuse the values for LAN dnsmasq.
- `PI_DNS_SERVERS` (Pi plane): public resolvers (default
  `1.1.1.1 8.8.8.8`) installed via NetworkManager `ipv4.dns` +
  `ipv4.ignore-auto-dns yes`, dhcpcd `static domain_name_servers` block,
  resolvconf head pin, or a direct `/etc/resolv.conf` write. The Pi keeps
  resolving apt / NTP / Pi Connect / the WireGuard endpoint hostname
  **even when the tunnel is down**, so DNS is never the reason remote
  management fails.

WireGuard `DNS =` vs this gateway:

- `DNS =` in `wg0.conf` is client-mode semantics: `wg-quick` rewrites the
  *host* resolv.conf when the tunnel is up (via resolvconf).
- Under Pi-bypass that would make the Pi's own DNS depend on `wg0`, defeating
  remote-management safety. Setup therefore **strips `DNS =`** from the
  installed `/etc/wireguard/wg0.conf` when `PI_BYPASS_ROUTING=true`.
- LAN client DNS is configured separately via dnsmasq (`HOME_DNS_*`). The
  prompt reuses any `DNS =` values from the source config as the LAN
  DNS default (confirm-or-override).

Rules:

- Both planes are only meaningful when `PI_BYPASS_ROUTING=true`. In
  legacy mode the Pi's own traffic goes through the tunnel anyway, so
  the tunnel-side already provides DNS.
- The default mode is `tunnel` only when the WireGuard config has **no**
  `DNS =` line, `AllowedIPs` includes a default route, **and**
  `LAN_FORWARD_MODE` is not `home`. If `DNS =` is present (or mode is
  home-only), default to `custom` with those / home servers and ask the
  operator whether to keep or override them.
- For `tunnel` mode every `server=<ip>@wg0` MUST use the `@wg0`
  source-interface binding. Without it, dnsmasq's outbound query
  follows the main table and goes via WAN (defeating the purpose);
  with it, dnsmasq sets `SO_BINDTODEVICE` so the kernel routes via
  wg0 unconditionally.
- `custom` mode entries must be covered by an `AllowedIPs` CIDR (a
  default-route `0.0.0.0/0` / `::/0` / split-default counts as coverage
  for that family); the input prompt validates this and warns loudly.
- dnsmasq must set `IGNORE_RESOLVCONF=yes` and `DNSMASQ_EXCEPT=lo` in
  `/etc/default/dnsmasq` so the Debian package does not register
  `127.0.0.1` with resolvconf and hijack the Pi's own resolver (breaks
  apt + WG endpoint hostname).
- Even when NetworkManager reapplies DNS successfully, also pin
  `PI_DNS_SERVERS` via resolvconf `head` when that package is installed
  (`/etc/resolv.conf` is often a resolvconf symlink NM does not fill).
  Verify/repair resolv.conf after dnsmasq restart and before `wg-quick up`.
- Legacy compat: a saved `HOME_DNS_SERVERS` without `HOME_DNS_MODE`
  (from before this redesign) is translated by
  `infer_home_dns_mode_legacy` to `MODE=custom` if non-empty, else
  `MODE=skip`. Never silently switch a legacy install to `tunnel`.
- Backups: `/etc/dnsmasq.conf.bak` is created the first time setup
  rewrites it; `/etc/resolv.conf.bak_gateway` is created the first time
  `do_configure_pi_dns` runs. Cleanup must restore both.
- `do_configure_pi_dns` must use `nmcli dev reapply` (not `nmcli con
  up`) so changing DNS does not bounce the WAN link and drop SSH for
  an operator on the WAN interface.

### Interface Picker UX

WAN/LAN selection in `select_interface` must stay operator-friendly on every Pi model:

- **Pi onboard Ethernet on an internal USB bus is still built-in.** Drivers
  `smsc95xx` (Pi 1/2/3B), `lan78xx` (Pi 3B+), and `bcmgenet` (Pi 4+) must
  label as `[ Pi built-in ]` / `bus=onboard`, even when sysfs path contains
  `/usb`. External dongles (`cdc_ncm`, `r8152`, `ax88179_178a`, …) stay
  `[ USB adapter ]`.
- **Defaults:** WAN prefers built-in/PCI; LAN prefers USB, then Wi-Fi. Cue
  shows the default **number** (Enter accepts it).
- **LAN step:** the already-chosen WAN iface stays visible but dimmed with
  `[ WAN — selected ]` and is not a selectable number.
- USB-bus classification still drives `BindsTo=` for true hotplug dongles;
  onboard smsc95xx/lan78xx must **not** get `BindsTo` (they are not removable).

### Optional WAN vs tunnel speedtest

Post-setup verification may run an Ookla CLI comparison (opt-in during the
input phase via `SPEEDTEST_ENABLED`, or later via manage menu / `--speedtest`):

- Direct test binds to `WAN_IFACE`; tunnel test binds to `wg0`
  (`SO_BINDTODEVICE`). Under Pi-bypass, an unbound Pi-local speedtest would
  only measure WAN — never skip the `wg0` bind for the tunnel leg.
- Prompt **before** `become_unattended`. Do not add interactive prompts during
  the speedtest itself (license flags: `--accept-license --accept-gdpr`).
- Install Ookla only when opted in; do not add it to base package deps.
- Failures must not abort setup (warn + continue). Live panel uses `ui_*`.

### Disconnect-Safe Execution

The execution phase must finish on its own even if the operator's terminal goes away (SSH drop, Pi Connect WebRTC failure, serial hang-up, laptop closed). Half-applied state on a remote Pi can be unrecoverable.

- After the input phase, the script must detach from its controlling terminal: ignore `SIGHUP`, close stdin, and route stdout/stderr to the persistent log file.
- Keep a dedicated FD open on the operator's TTY for the progress box/spinner. Detailed command output (apt, wg-quick, systemctl) stays in the log only — do **not** auto-tail the full log onto the TTY (that interleaves with the spinner and makes the UI unreadable). Operators who want the raw stream can `tail -f` the log themselves.
- Detect remote-management daemons (Raspberry Pi Connect, etc.) before the execution phase and warn explicitly when WireGuard `AllowedIPs` includes a default route (`0.0.0.0/0`, `::/0`, or `0.0.0.0/1` + `128.0.0.0/1`) - that single setting is the most common way a remote-managed Pi loses its management plane after `wg-quick up`.
- Never add a prompt after the input phase. Any new question must move into the input-collection block.

## Living Decisions (Automatic Maintenance)

When a user prompt introduces a new durable project decision:

1. Update this `AGENTS.md` with that decision.
2. Update relevant `.cursor/rules/*.mdc` so the behavior is enforced in future sessions.
3. Keep additions concise and action-oriented.

Treat this as required maintenance, not optional documentation.
