# Raspberry Pi Site-to-Site VPN Gateway (WireGuard)
SEO-friendly terms: *Raspberry Pi site-to-site VPN*, *WireGuard gateway*, *home network extension*, *remote office Wi‑Fi to home network*, *plug-and-play VPN router*.

## Pitch
Set up a **Raspberry Pi WireGuard site-to-site VPN** in minutes. One Ethernet cable in, optional Pi Wi‑Fi out, and every device on that Wi‑Fi (or LAN) behaves as if it's on your **home network**—no router changes, no port forwarding, fully NAT-friendly. Perfect for remote offices, cabins, and temporary sites.

---

Build a **plug-and-play site-to-site VPN** with a single **Raspberry Pi** and **one Ethernet cable**. The script turns the Pi into:
- A **WireGuard VPN client** that extends your home network to a remote site.
- A **DHCP router + NAT** for a private subnet.
- An optional **Wi‑Fi access point** so every device on that Wi‑Fi "pretends" to be on your home network—no router changes needed.

## Why this is simple
- Works behind **NAT/CGNAT** (outbound WireGuard only; no port forwarding required).
- Zero router config at the remote site—plug in WAN Ethernet, run one script.
- If you enable Wi‑Fi, the Pi broadcasts an SSID that tunnels straight to home.
- **Survives reboots**: all services and configurations persist automatically.

## Hardware
- Raspberry Pi 4 (or similar Pi; Wi‑Fi-capable if you want an AP)
- One Ethernet cable (WAN to the existing onsite network)
- Optional: USB Ethernet adapter if you prefer wired LAN plus Wi‑Fi WAN/LAN

## Software / Files
- Raspberry Pi OS Lite (Bookworm or later recommended)
- WireGuard peer config from your home network (e.g., `wg0.conf`/peer file)

## Quick start (about 5 minutes)
1. **Prep the Pi**
   - Flash Raspberry Pi OS Lite, enable SSH, boot, then:
     ```bash
     sudo apt-get update && sudo apt-get upgrade -y
     ```
2. **Get the project**
   ```bash
   git clone https://github.com/etokheim/raspberrypi-site2site-wireguard.git
   cd raspberrypi-site2site-wireguard
   ```
3. **Copy your WireGuard peer config** to the Pi (e.g., `/home/pi/wg-peer.conf`).
4. **Run the entrypoint** (prompts for everything)
   ```bash
   sudo ./gateway-manage-or-setup.sh
   ```
  - Select WAN and LAN interfaces (Enter accepts defaults). The picker now shows state/IP/MAC/driver and whether the NIC appears USB-backed.
   - If LAN is Wi‑Fi (e.g., `wlan0`), enter SSID/password; hostapd is auto-configured.
   - Provide the WireGuard config path (tab completion enabled).
   - Opt into a **static WAN IP** (recommended): the script detects the upstream router and suggests the second IP in the subnet (e.g. router `192.168.1.1` → `192.168.1.2`). You can override IP, prefix, gateway and DNS.
   - Opt into WAN firewall hardening (allow SSH + WireGuard, drop other inbound).
   - Opt into automatic security updates (nightly at 03:00).
   - Opt into hardware watchdog (auto-reboot on system hang).
   - Review the progress box, then confirm to apply.
5. **Connect devices**
   - Wired: plug a switch/AP into the Pi's LAN port.
   - Wi‑Fi: connect to the SSID you set. Clients get `10.10.10.x` and route through WireGuard to your home network.

## Command-line options

```bash
sudo ./gateway-manage-or-setup.sh [OPTIONS]
```

| Option | Description |
|--------|-------------|
| *(none)* | Interactive menu (setup/cleanup/start/stop) |
| `--setup` | Run setup wizard |
| `--cleanup` | Remove gateway configuration |
| `--start` | Start gateway services (WireGuard + dnsmasq + hostapd) |
| `--stop` | Stop gateway services |
| `--yes` | Non-interactive mode (use existing config, no prompts) |
| `--help` | Show usage |

## What the script sets up
- **WireGuard** at `/etc/wireguard/wg0.conf`, `wg-quick@wg0` enabled, PostUp/PostDown iptables rules.
- **Routing/NAT**: iptables forwarding and MASQUERADE from LAN → `wg0` (WAN MASQUERADE as secondary).
- **Pi-bypass routing (recommended)**: forwarded LAN traffic goes through `wg0`; the Pi's *own* outbound (apt, Pi Connect, NTP, DNS, the WireGuard handshake itself) stays on WAN. See [How traffic is routed](#how-traffic-is-routed) below.
- **DHCP/DNS**: dnsmasq on the LAN/AP subnet. With Pi-bypass routing the dual-DNS plane separates LAN client DNS (via `HOME_DNS_SERVERS` through the tunnel - geo-correct) from the Pi's own DNS (via `PI_DNS_SERVERS` over WAN - always reachable, even with the tunnel down). See [DNS plane separation](#dns-plane-separation-dual-dns-optional-but-recommended).
- **Static IP (LAN)**: gateway `10.10.10.1/24` on the LAN/AP interface.
- **Static IP (WAN, optional)**: fixed address on the upstream interface (suggested as the second IP in the router's subnet, e.g. `192.168.1.2` if the router is `192.168.1.1`).
- **Access Point (optional)**: hostapd with your SSID/password when LAN is wireless.
- **Firewall (optional)**: hardened INPUT rules on WAN (allows SSH, WireGuard; drops other inbound).
- **Service watchdog**: systemd restart policies for dnsmasq, WireGuard, hostapd (auto-restart on crash).
- **Boot ordering hardening**: a persistent `vpn-gateway-lan.service` plus systemd drop-ins so LAN comes up before dnsmasq/hostapd/WireGuard.
- **Hardware watchdog (optional)**: kernel-level auto-reboot if system hangs.
- **Auto-updates (optional)**: unattended-upgrades for security patches.
- **Persistence**: all settings survive reboots (systemd services, static IPs, iptables).

## How traffic is routed

The setup wizard asks once whether to enable **Pi-bypass routing** (recommended). The two modes differ only in routing; the WireGuard config and firewall are otherwise identical.

### Pi-bypass routing (recommended)

```
                    ┌───────────────────┐
   LAN client  ────►│  Pi (gateway)     │
   10.10.10.x       │                   │
   (forwarded,      │  iif=LAN_IFACE    │
    iif=LAN_IFACE)  │      │            │     ┌─ encrypted ─┐
                    │      ▼            ├────►│   wg0       │──► home WG peer
                    │  table 200:       │     │             │
                    │  default dev wg0  │     └─────────────┘
                    │                   │
                    │  Pi-local         │
                    │  (apt, Pi Connect,│     ┌─ direct ────┐
   Pi process  ─────│   NTP, DNS, WG    ├────►│ WAN gateway │──► Internet
   (no iif)         │   handshake) →    │     │             │
                    │  main: default    │     └─────────────┘
                    │  via WAN gw       │
                    └───────────────────┘
```

- **LAN client traffic** is forwarded through the Pi. The kernel sees `iif=$LAN_IFACE`, matches an `ip rule` at priority 100, and looks up routing in table 200, where the default route is `dev wg0`. Encrypted packets go to the home peer.
- **Pi-local traffic** (anything originating on the Pi itself) has no `iif` set. It skips the priority-100 rule and falls through to the **main** table, where the default route is the WAN gateway. The Pi can still reach the home subnet via `wg0` because each non-default `AllowedIPs` entry (e.g. `10.33.33.0/24`) is also added as an explicit route in the main table.
- **WireGuard's own UDP handshake** is Pi-local traffic; it goes via WAN like any other Pi process. There is no chicken-and-egg problem when the tunnel restarts.

#### Kill-switch semantics (intentional)
- If `wg0` is down, packets routed through table 200 hit a route whose `dev wg0` no longer exists - the kernel drops them. **LAN clients lose Internet** rather than silently leaking via the Pi's WAN.
- The Pi itself stays online because its traffic uses the main table, which is untouched. Remote management via Pi Connect, SSH-over-Internet, and apt continue to work.
- This means an outage of the home WG peer disconnects LAN clients but never disconnects you from the Pi.

#### DNS plane separation (dual-DNS, recommended)

LAN clients query the Pi's `dnsmasq`. dnsmasq itself runs on the Pi, so where its *upstream* lookups go depends on which **mode** the operator picked at the prompt (`HOME_DNS_MODE` in `vpn-gateway.conf`):

- **`tunnel` (default)** - dnsmasq forwards to public DNS bound to `wg0`: `server=1.1.1.1@wg0`, `server=8.8.8.8@wg0`. Each query exits via the tunnel; the home peer NATs it out from the home location, so DNS responses are geo-anchored at home. Works without any DNS server on the home network. Requires `AllowedIPs` to cover the chosen public DNS IPs (typically via `0.0.0.0/0`).
- **`custom`** - dnsmasq forwards to a specific home-network DNS server you specify (e.g. Pi-hole or AdGuard Home at `10.33.33.1`). Use this if you want LAN clients to also pick up local hostname resolution from your home DNS. The destination IP must be covered by an `AllowedIPs` entry; the input prompt validates this.
- **`skip`** - dnsmasq falls back to the Pi's `/etc/resolv.conf` (which points at `PI_DNS_SERVERS` over WAN). LAN DNS keeps working when the tunnel is down, but resolution geo-leaks to the WAN ISP's location.

In all three modes, the **Pi's own** DNS is configured separately via `PI_DNS_SERVERS` (default `1.1.1.1 8.8.8.8`) and goes via WAN. apt, NTP, Pi Connect, and the WireGuard endpoint hostname keep resolving even when the tunnel is down, so remote management never breaks because of DNS.

A WireGuard `DNS =` line in your peer config is **not** the same thing: that is client-mode (`wg-quick` rewriting the host resolv.conf). Under Pi-bypass setup strips `DNS =` from the installed `wg0.conf` so it cannot override `PI_DNS_SERVERS`. If those addresses are your home resolver (Pi-hole, etc.), the LAN-DNS prompt offers them as a custom-mode suggestion — press Enter for tunnel-exit, or type the IPs / `wg` to reuse them for LAN clients.

```
LAN client ──DHCP-supplied DNS──> Pi (10.10.10.1)
                                       │
                                       │ dnsmasq
                                       ▼
                  ┌───── HOME_DNS_MODE=tunnel ─────┐
                  │  server=1.1.1.1@wg0            │ ─► wg0 ─► home peer NATs ─► public DNS
                  │  (default; geo-correct)        │           (response geo-anchored at home)
                  └────────────────────────────────┘
                  ┌───── HOME_DNS_MODE=custom ─────┐
                  │  server=<your home DNS IP>     │ ─► wg0 ─► home DNS server (Pi-hole etc.)
                  └────────────────────────────────┘
                  ┌───── HOME_DNS_MODE=skip ───────┐
                  │  uses Pi's /etc/resolv.conf    │ ─► WAN ─► public DNS (geo-leaks)
                  └────────────────────────────────┘

Pi-local lookups (apt, NTP, Pi Connect, wg endpoint) ─► /etc/resolv.conf
                                                       (PI_DNS_SERVERS) ─► WAN ─► always works
```

Kill-switch: in `tunnel` and `custom` modes, when `wg0` is down LAN DNS stops resolving (the upstream packet has no route). The Pi itself keeps resolving via `PI_DNS_SERVERS` over WAN, so remote management is unaffected.

### Legacy / full-tunnel-including-Pi mode

If you say *No* to Pi-bypass at the prompt, `wg-quick` manages routes the standard way: when your `AllowedIPs` contains `0.0.0.0/0`, the Pi's *own* outbound traffic also flows through the tunnel. This is appropriate only if your home WireGuard peer NATs the Pi's traffic out to the Internet. Without that NAT, the Pi loses Pi Connect, apt, and any SSH session that comes in via its public IP the moment `wg0` comes up. The setup wizard warns about this on the SSH-safety check.

## Default network plan (changeable at prompts)
- Subnet: `10.10.10.0/24`
- Gateway: `10.10.10.1`
- DHCP pool: `10.10.10.10 - 10.10.10.250`
- Note: the script locks LAN subnets to /24. If you enter another prefix, it will coerce it to a /24 in the same third-octet block (e.g., `192.168.50.0/20` becomes `192.168.50.0/24`).

## Verify it works
On the Pi (with Pi-bypass enabled, this shows the *WAN* egress IP — not home):
```bash
wg show
curl https://ifconfig.me   # Pi-local traffic stays on WAN
```
On a client connected to the Pi LAN/AP (this shows the *home* egress IP):
```bash
ping 10.10.10.1                 # gateway reachability
ping 1.1.1.1                    # routing/NAT via the tunnel
curl https://ifconfig.me        # should show your home/central egress IP
nslookup google.com 10.10.10.1  # DNS via dnsmasq
```

## Logs and artifacts
| File | Description |
|------|-------------|
| `logs/vpn_setup.log` | Setup script log |
| `logs/vpn_cleanup.log` | Cleanup script log |
| `vpn-gateway.conf` | Saved configuration (git-ignored) |

## Cleanup / revert
```bash
sudo ./gateway-manage-or-setup.sh --cleanup
# or directly:
sudo ./scripts/cleanup-gateway.sh
```

Cleanup will:
- Stop/disable WireGuard, dnsmasq, hostapd (if running)
- Remove WAN firewall rules (if enabled)
- Remove NAT/forward iptables rules; disable IP forwarding
- Tear down Pi-bypass routing (the `iif=LAN` `ip rule`, the table-200 routes, IPv6 mirrors)
- Restore Pi-local DNS settings (NetworkManager `ipv4.dns`, dhcpcd `static domain_name_servers` block, `/etc/resolv.conf` from backup)
- Restore NetworkManager/dhcpcd to DHCP (on both LAN and WAN, if a static WAN IP was configured)
- Remove watchdog configurations
- Remove unattended-upgrades config (if auto-updates were enabled)
- Optionally delete the saved config file

## Troubleshooting

| Symptom | Solution |
|---------|----------|
| **wg-quick DNS errors** | Ensure `resolvconf` is installed (handled by setup) and the endpoint hostname resolves. |
| **Clients get DHCP but no internet** | Check `iptables -t nat -S \| grep MASQUERADE` and `iptables -S FORWARD`. Verify WireGuard handshake with `wg show`. |
| **Gateway not working after reboot** | Check `systemctl status vpn-gateway-lan wg-quick@wg0 dnsmasq hostapd`, then run `sudo ./gateway-manage-or-setup.sh --start`. |
| **dnsmasq says unknown interface** | Re-run `sudo ./gateway-manage-or-setup.sh --setup`, reselect the correct LAN interface using the metadata shown, then apply and reboot-test. |
| **Wi-Fi AP not visible** | Check `rfkill list` for blocked wlan. Run `sudo rfkill unblock wlan`. |
| **Using a wired AP instead of Pi Wi‑Fi** | Choose the Pi's Wi‑Fi as WAN and plug your wired AP/switch into the Pi's Ethernet as LAN. |

For deeper boot diagnostics:

```bash
sudo systemctl status vpn-gateway-lan dnsmasq hostapd wg-quick@wg0
sudo journalctl -b -u vpn-gateway-lan -u dnsmasq -u hostapd -u wg-quick@wg0 --no-pager
ip -br link
ip -br addr
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Remote Site                              │
│  ┌──────────┐      ┌─────────────────────────────────────────┐  │
│  │  Client  │──────│            Raspberry Pi                 │  │
│  │ Devices  │ WiFi │  ┌───────┐    ┌─────┐    ┌──────────┐   │  │
│  │10.10.10.x│ or   │  │dnsmasq│────│ NAT │────│WireGuard │   │  │
│  └──────────┘ LAN  │  │ DHCP  │    │     │    │   wg0    │   │  │
│                    │  └───────┘    └─────┘    └────┬─────┘   │  │
│                    └───────────────────────────────┼─────────┘  │
│                                                    │            │
└────────────────────────────────────────────────────┼────────────┘
                                                     │ UDP tunnel
                                                     ▼
┌────────────────────────────────────────────────────────────────┐
│                         Home Network                           │
│                    ┌──────────────────┐                        │
│                    │ WireGuard Server │                        │
│                    │   (your router)  │                        │
│                    └──────────────────┘                        │
└────────────────────────────────────────────────────────────────┘
```

