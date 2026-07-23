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

- Forwarded packets (`iif=$LAN_IFACE`) -> table 200 -> default `dev wg0`.
- Locally-generated packets (no `iif`) -> main table -> WAN.
- Per-peer subnets (non-default `AllowedIPs` entries) get explicit
  `dev wg0` routes in BOTH the main table (so the Pi reaches them) and
  table 200 (so LAN clients reach them via the tunnel).
- When `wg0` is down, table-200 packets drop (kill-switch). Pi-local
  traffic continues via WAN, preserving remote management.

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

- `HOME_DNS_MODE` (LAN client plane) - `tunnel` (default) | `custom` |
  `skip`.
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
  When the WireGuard config has a `DNS =` line, those addresses are offered
  as the custom-mode suggestion (and can be reused by typing `wg` at the
  prompt). `DNS =` itself is *not* applied under Pi-bypass - see below.
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
  prompt surfaces any `DNS =` values found in the source config as a
  reusable custom-mode suggestion.

Rules:

- Both planes are only meaningful when `PI_BYPASS_ROUTING=true`. In
  legacy mode the Pi's own traffic goes through the tunnel anyway, so
  the tunnel-side already provides DNS.
- The default mode is `tunnel`. It is the simplest UX (no need to know
  any home DNS IP), and only `custom` mode requires AllowedIPs
  validation by the input prompt.
- For `tunnel` mode every `server=<ip>@wg0` MUST use the `@wg0`
  source-interface binding. Without it, dnsmasq's outbound query
  follows the main table and goes via WAN (defeating the purpose);
  with it, dnsmasq sets `SO_BINDTODEVICE` so the kernel routes via
  wg0 unconditionally.
- `custom` mode entries must be covered by an `AllowedIPs` CIDR (a
  default-route `0.0.0.0/0` / `::/0` / split-default counts as coverage
  for that family); the input prompt validates this and warns loudly.
- dnsmasq must set `IGNORE_RESOLVCONF=yes` in `/etc/default/dnsmasq` so
  the Debian package does not register `127.0.0.1` with resolvconf and
  hijack the Pi's own resolver (breaks apt + WG endpoint hostname).
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
