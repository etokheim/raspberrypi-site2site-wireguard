# Raspberry Pi Site-to-Site VPN Gateway (WireGuard)

_TLDR - Example use cases:_
- _Let's a Raspberry Pi create a WIFI network on which all connected clients think they are on your home network - even though they are off-site!_
- _Create a safe and private WIFI while traveling_
- _Create an extension of your home network_

---

Build a **plug-and-play site-to-site VPN** with a single **Raspberry Pi** and **one Ethernet cable**. The script turns the Pi into:
- A **WireGuard VPN client** that extends your home network to a remote site.
- A **DHCP router + NAT** for a private subnet.
- An optional **Wi‑Fi access point** so every device on that Wi‑Fi “pretends” to be on your home network - no router changes needed.

SEO-friendly terms: *Raspberry Pi site-to-site VPN*, *WireGuard gateway*, *home network extension*, *remote office Wi‑Fi to home network*, *plug-and-play VPN router*.

## Why this is simple
- Works behind **NAT/CGNAT** (outbound WireGuard only; no port forwarding).
- Zero router config at the remote site—plug in WAN Ethernet, run one script.
- If you enable Wi‑Fi, the Pi broadcasts an SSID that tunnels straight to home.

## Hardware
- Raspberry Pi 4 (or similar Pi; Wi‑Fi-capable if you want an AP)
- One Ethernet cable (WAN to the existing onsite network)
- Optional: USB Ethernet adapter if you prefer wired LAN plus Wi‑Fi WAN/LAN

## Software / Files
- Raspberry Pi OS Lite
- WireGuard peer config from your home network (e.g., `wg0.conf`/peer file)

## Quick start (about 5 minutes)
1) Prep the Pi  
   - Flash Raspberry Pi OS Lite, enable SSH, boot, then:  
     `sudo apt-get update && sudo apt-get upgrade -y`
2) Get the project  
   ```bash
   git clone https://github.com/your/repo.git vpn-project
   cd vpn-project
   ```
3) Copy your WireGuard peer config to the Pi (e.g., `/home/pi/wg-peer.conf`).
4) Run the entrypoint (prompts for everything)  
   ```bash
   sudo ./gateway-manage-or-setup.sh
   ```
   - Select WAN and LAN (Enter accepts defaults).  
   - If LAN is Wi‑Fi (e.g., `wlan0`), enter SSID/password; hostapd is auto-configured.  
   - Provide the WireGuard config path (tab completion enabled).  
   - Opt into WAN firewall hardening (allow SSH + WireGuard, drop other inbound).  
   - Opt into automatic updates (all packages nightly at 03:00, logs only; max 20 update logs kept).  
   - Review the framed “Planned changes” summary, then confirm to apply.
5) Connect devices  
   - Wired: plug a switch/AP into the Pi’s LAN.  
   - Wi‑Fi: connect to the SSID you set. Clients get `10.10.10.x` and route through WireGuard to your home network.

## What the script sets up
- **WireGuard** at `/etc/wireguard/wg0.conf`, `wg-quick@wg0` enabled, PostUp/PostDown iptables rules.
- **Routing/NAT**: iptables forwarding and MASQUERADE from LAN → `wg0` (WAN MASQUERADE as secondary).
- **DHCP/DNS**: dnsmasq on the LAN/AP subnet; DNS served by the Pi.
- **Static IP**: gateway `10.10.10.1/24` on the LAN/AP interface.
- **Access Point (optional)**: hostapd with your SSID/password when LAN is wireless.
- **Resilience**: enforces NAT rules after bring-up in case PostUp is skipped.

## Default network plan (changeable at prompts)
- Subnet: `10.10.10.0/24`
- Gateway: `10.10.10.1`
- DHCP pool: `10.10.10.10 - 10.10.10.250`

## Verify it works
On the Pi:
```bash
wg show
curl https://ifconfig.me   # should show your home/central egress IP
```
On a client connected to the Pi LAN/AP:
```bash
ping 10.10.10.1                 # gateway reachability
ping 1.1.1.1                    # routing/NAT
nslookup google.com 10.10.10.1  # DNS via dnsmasq
```

## Logs and artifacts
- Setup log: `logs/vpn_setup.log`
- Cleanup log: `logs/vpn_cleanup.log`
- Update logs (if auto-updates enabled): `logs/Update log YYYY-MM-DD.log` (max 20 kept)
- Config file: `vpn-gateway.conf` (git-ignored)

## Cleanup / revert
- Via entrypoint: `sudo ./gateway-manage-or-setup.sh --cleanup`
- Direct script: `sudo ./scripts/cleanup-gateway.sh`

Cleanup shows a planned-changes summary and will:
- Stop/disable WireGuard, dnsmasq, hostapd (if running)
- Remove WAN firewall rules (if they were enabled)
- Flush firewall/NAT rules; reset IP forwarding
- Restore NetworkManager/dhcpcd to DHCP
- Remove unattended-upgrades config/timers if auto updates were enabled

## Troubleshooting
- **wg-quick DNS errors**: ensure `resolvconf` is installed (handled by the script) and the endpoint hostname resolves.  
- **Clients get DHCP but no internet**: check `iptables -t nat -S | grep MASQUERADE` and `iptables -S FORWARD | egrep 'wlan0|wg0'`. The script enforces these rules, but verify after reboots.  
- **Using a wired AP instead of Pi Wi‑Fi**: choose the Pi’s Wi‑Fi as WAN and plug your wired AP/switch into the Pi’s Ethernet as LAN.

## One-line pitch
Set up a **Raspberry Pi WireGuard site-to-site VPN** in minutes. One Ethernet cable in, optional Pi Wi‑Fi out, and every device on that Wi‑Fi (or LAN) behaves as if it’s on your **home network**—no router changes, no port forwarding, fully NAT-friendly. Perfect for remote offices, cabins, and temporary sites.
