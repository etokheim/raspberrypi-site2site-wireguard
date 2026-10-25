# Guided TWO-WAY site access (IPv4)

Use these labels throughout setup:

- **Pi-side LAN**: devices plugged into the Pi's LAN port or Wi-Fi AP. For example, Bjoa's `10.3.0.0/24`, gateway `10.3.0.1`.
- **VPN-server-side networks**: devices behind the VPN server, including networks at other sites reached through that server. Enter their actual IPv4 networks; ask that side's administrator if unsure.
- **WAN**: the Pi's upstream Internet connection, not its LAN. For example, `192.168.10.197/24` is on WAN network `192.168.10.0/24`.

TWO-WAY is the recommended default **only for new installs**. Existing configurations without `SITE_*` fields keep their existing **OUTBOUND NAT** behavior, even with `--apply`, `--start`, or a full reconfigure. Nothing is silently migrated.

## Choose access

New setup asks for site access, then separately asks how Pi-side devices use the Internet. To migrate an existing installation:

```bash
sudo ./gateway-manage-or-setup.sh --edit
```

Choose **13: Two-way site access**, then **1: TWO-WAY**. Enter VPN-server-side CIDRs separated by spaces, for example `192.168.20.0/24 192.168.30.0/24` (examples only, not automatic defaults). Select who may connect into the Pi-side LAN:

1. **Selected networks (recommended default for a new routed selection)**. Allow all protocols in both directions between those networks and the Pi-side LAN. Trust devices in the selected networks: they can reach Pi-side services. This does not open access to arbitrary Internet peers; external routing and device firewalls still apply.
2. **Only specified source networks/devices**. Choose narrower inbound access if needed. For one device, enter a `/32`, such as `192.168.20.5/32`.
3. **Outbound only**. Keep real device addresses and return routes, but do not allow new VPN-server-side connections into the Pi-side LAN.

Confirm that you have arranged the external routing below. The Pi cannot configure the VPN server for you. Choosing OUTBOUND NAT instead reverses the Pi-side site exemptions/access rules; Internet NAT stays enabled. Existing connections may need to reconnect because NAT decisions are cached in conntrack.

TWO-WAY requires **Pi-bypass**. It keeps the Pi's Internet default route, Pi Connect, apt and endpoint DNS on WAN. If migration enables Pi-bypass, setup also asks for the two DNS planes. To disable Pi-bypass later, first switch site access back to OUTBOUND NAT.

Saved routed selections retain their chosen access policy, including restricted-source and outbound-only settings, when you accept the prompts with Enter.

## Required VPN-server-side work

For a Pi with LAN `10.3.0.0/24` and WireGuard address `10.1.100.6/32`:

1. On the **VPN server's peer entry for this Pi**, add `10.3.0.0/24` to **Networks behind client** (or the peer's `AllowedIPs`). Retain the peer's tunnel address as appropriate. This tells the server that the LAN belongs behind this peer, not another peer.
2. Ensure the VPN server/router actually routes `10.3.0.0/24` through that Pi peer. Some products create the route automatically; verify it.
3. Allow forwarding between the tunnel and selected networks, plus return traffic. Avoid server-side NAT between sites if you want the Pi-side access restrictions to see original source addresses.
4. If other networks are reached using **UniFi Site Magic**, advertise `10.3.0.0/24` from the **VPN-server-side gateway** to those sites. A WireGuard peer entry alone does not advertise a third-party subnet through Site Magic. Verify that the platform supports this advertisement and that the other gateways learn a return route. Otherwise add supported static routes / use an appropriate routing design.
5. Pi-side devices must use `10.3.0.1` as their default gateway (normally supplied by DHCP), or have explicit return routes via the Pi. Allow the desired service in each destination device's firewall.

On the **Pi's peer configuration**, `AllowedIPs` must cover every selected VPN-server-side CIDR. `0.0.0.0/0` provides coverage but does **not** tell this script which site networks you want; enter them explicitly. The script does not rewrite peer `AllowedIPs` or change the VPN server.

Networks must not overlap each other, the Pi-side LAN, or the Pi WAN. Use canonical network addresses (`10.3.0.0/24`, not `10.3.0.0./24` or `10.3.0.1/24`). Default/split-default routes are not site networks. A connected WAN address is required for the overlap check (or configure a static WAN address during setup). Python 3 is required for validation and is normally present on Raspberry Pi OS; if absent, install it before setup: `sudo apt-get install python3`.

## Saved settings and routing behavior

Example, after explicit migration:

```bash
SITE_ROUTING_MODE="routed"        # nat preserves legacy behavior
SITE_REMOTE_CIDRS="192.168.20.0/24 192.168.30.0/24"
SITE_INBOUND_ACCESS="restricted"  # sites | restricted | outbound
SITE_INBOUND_SOURCES="192.168.20.5/32"  # only for restricted; otherwise empty
PI_BYPASS_ROUTING="true"
```

`LAN_FORWARD_MODE=all` still sends Pi-side device Internet traffic through the VPN; `home` sends only the selected VPN-server-side networks through the VPN, with other Internet traffic over WAN. This is **independent** of two-way access. Main and table 200 get explicit selected-network routes, so the Pi and Pi-side devices send site responses through WireGuard rather than accidentally through WAN. No default route is added to the main table.

An owned FORWARD chain permits established replies and only the chosen new inbound sources. A NAT chain exempts both directions between the Pi-side LAN and selected site networks **before** the existing WireGuard MASQUERADE. Internet traffic still uses NAT. Changing mode, networks or interfaces replaces these chains; stop/cleanup removes them. `--start` repairs saved hooks and missing service-ordering units without prompting; `--apply` reapplies saved settings.

**IPv4 scope only:** this feature does not configure IPv6 site routes, IPv6 access rules, IPv6 NAT exemptions or an IPv6 leak-prevention policy. An IPv6 `AllowedIPs` entry is not proof that two-way IPv6 is configured. Existing legacy IPv6 behavior is not a complete site-to-site implementation either.

## Verify after applying on the Pi

These are checks for the operator, not commands the test suite runs on a live network:

- `ip route get <VPN-server-side-device-IP>` should use `wg0`.
- `ip route get 1.1.1.1` (unbound Pi traffic) should still use WAN.
- `ip route show table 200` should contain the selected site routes (and a VPN default only in `all` Internet mode).
- Start a **new** connection from an allowed VPN-server-side device to a Pi-side device; then try a disallowed source. Test the actual application, not just ping.
- Check that the destination sees the original source address. If not, inspect VPN-server-side NAT and old conntrack state.
- Existing `--verify-routes` checks routing/DNS/public egress; it cannot prove that external routers, Site Magic advertisements or device firewalls are correct.

## Rootless regression tests

```bash
python3 -m unittest discover -s tests -v
for f in scripts/*.sh gateway-manage-or-setup.sh; do bash -n "$f" || exit; done
```

Tests use stateful mock `ip`, `iptables`, `wg-quick` and service calls; they require no root, do not install anything and make no live network changes.
