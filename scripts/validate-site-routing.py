#!/usr/bin/env python3
"""Validate untrusted IPv4 site-routing inputs before shell command generation."""
import ipaddress
import re
import sys


def networks(value, label, required=True):
    tokens = value.replace(',', ' ').split()
    if required and not tokens:
        raise ValueError(f'{label}: enter at least one IPv4 network, for example 192.168.20.0/24')
    result = []
    for token in tokens:
        net = ipaddress.ip_network(token, strict=True)
        if net.version != 4 or str(net) != token or '/' not in token or net.prefixlen <= 1:
            raise ValueError(f'{label}: use canonical IPv4 CIDRs, not default/split-default routes: {token}')
        if any(net.overlaps(other) for other in result):
            raise ValueError(f'{label}: duplicate or overlapping networks: {token}')
        result.append(net)
    return result


def validate(mode, lan, remote, access, sources, cfg, wan, lan_iface, wan_iface, bypass):
    if mode not in ('nat', 'routed'):
        raise ValueError('SITE_ROUTING_MODE must be nat or routed')
    if mode == 'nat':
        return
    if bypass != 'true':
        raise ValueError('TWO-WAY routing requires Pi-bypass enabled to keep Pi Connect on WAN')
    for iface in (lan_iface, wan_iface):
        if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}', iface):
            raise ValueError('Invalid interface name')
    local = networks(lan, 'Pi-side LAN')
    if len(local) != 1:
        raise ValueError('Pi-side LAN must be one CIDR')
    sites = networks(remote, 'VPN-server-side networks')
    wans = [ipaddress.ip_network(s, strict=False) for s in wan.split()]
    if any(local[0].overlaps(n) for n in wans if n.version == 4):
        raise ValueError('Pi-side LAN overlaps WAN; use separate networks on the two interfaces')
    for site in sites:
        if any(site.overlaps(n) for n in local + wans if n.version == 4):
            raise ValueError(f'VPN-server-side network {site} overlaps the Pi-side LAN or WAN')
    allowed = []
    section = ''
    with open(cfg, encoding='utf-8') as stream:
        for line in stream:
            line = line.split('#', 1)[0].strip()
            if line.startswith('['):
                section = line.lower()
            elif section == '[peer]' and re.match(r'AllowedIPs\s*=', line, re.I):
                allowed.extend(ipaddress.ip_network(s.strip(), strict=False)
                               for s in line.split('=', 1)[1].split(','))
    coverage = list(ipaddress.collapse_addresses(n for n in allowed if n.version == 4))
    if any(not any(site.subnet_of(n) for n in coverage) for site in sites):
        raise ValueError('Every VPN-server-side network must be covered by the actual peer AllowedIPs')
    if access not in ('sites', 'restricted', 'outbound'):
        raise ValueError('SITE_INBOUND_ACCESS must be sites, restricted or outbound')
    selected = networks(sources, 'Allowed access sources', required=access == 'restricted')
    if access != 'restricted' and selected:
        raise ValueError('Access sources are only used with restricted access; clear SITE_INBOUND_SOURCES')
    if any(not any(n.subnet_of(site) for site in sites) for n in selected):
        raise ValueError('Allowed access sources must be inside the selected VPN-server-side networks')


if __name__ == '__main__':
    try:
        validate(*sys.argv[1:])
    except (ValueError, OSError, TypeError) as exc:
        print(f'Site routing: {exc}', file=sys.stderr)
        sys.exit(1)
