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
    sed -i 's/^net.ipv4.ip_forward=1/#net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sysctl -p

    echo "Removing static IP configuration from dhcpcd.conf..."
    if [ -f /etc/dhcpcd.conf ]; then
        # Create a backup
        cp /etc/dhcpcd.conf /etc/dhcpcd.conf.bak.restore
        
        # We need to remove the block we added. 
        # Since we just appended, this is tricky to remove programmatically without markers.
        # But we know the structure: interface $IFACE \n static ip...
        # For safety, let's just warn user or try to revert if we had a backup from setup?
        # A simpler approach for cleanup script without state is to ask user or just comment it out.
        
        # Let's try to remove lines matching our LAN config pattern if we can identify them?
        # Or, since this is a dedicated Pi, maybe we don't need to be surgically precise?
        # Let's just restore the backup if it exists? No, setup didn't make one (my bad).
        # Let's tell the user.
        echo "  [ACTION REQUIRED] Please manually remove static IP configuration for your LAN interface from /etc/dhcpcd.conf"
    fi
    
    # Restart networking/dhcpcd to pick up changes (revert to DHCP client on LAN port if applicable)
    systemctl restart dhcpcd || true

    echo "Cleanup Complete. The Pi is returned to a state without VPN routing."
}

main

