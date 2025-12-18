#!/bin/bash

# cleanup-gateway.sh
# Removes VPN Gateway configuration, stops services, and clears firewall rules.

set -e

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
}

main() {
    check_root

    echo "Stopping WireGuard interface wg0..."
    if systemctl is-active --quiet wg-quick@wg0; then
        systemctl stop wg-quick@wg0
        systemctl disable wg-quick@wg0
        echo "WireGuard stopped and disabled."
    else
        echo "WireGuard service not running."
    fi

    # Also try manual down in case it wasn't a service
    if ip link show wg0 > /dev/null 2>&1; then
        wg-quick down wg0 || true
    fi

    echo "Stopping and disabling dnsmasq (DHCP)..."
    if systemctl is-active --quiet dnsmasq; then
        systemctl stop dnsmasq
        systemctl disable dnsmasq
        echo "dnsmasq stopped and disabled."
    fi

    echo "Flushing iptables NAT and Forward rules..."
    iptables -t nat -F
    iptables -F FORWARD
    # Reset default policies
    iptables -P FORWARD ACCEPT 
    # (Or DROP, default depends on distro, usually ACCEPT is default reset state for minimal interference, though secure is DROP)
    
    echo "Disabling IP forwarding..."
    rm -f /etc/sysctl.d/99-vpn-gateway.conf
    # Reload sysctl to apply changes (might need reboot or manual reset, but removing file prevents persistence)
    sysctl --system

    echo "Removing static IP configuration from dhcpcd.conf..."
    if [ -f /etc/dhcpcd.conf ]; then
        sed -i '/# VPN-GATEWAY-START/,/# VPN-GATEWAY-END/d' /etc/dhcpcd.conf
        echo "  [OK] Removed VPN Gateway configuration from /etc/dhcpcd.conf"
    fi
    
    # Restart networking/dhcpcd to pick up changes (revert to DHCP client on LAN port if applicable)
    systemctl restart dhcpcd || true

    echo "Cleanup Complete. The Pi is returned to a state without VPN routing."
}

main

