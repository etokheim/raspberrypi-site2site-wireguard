#!/bin/bash

# setup-vpn-gateway.sh
# Configures Raspberry Pi as a VPN Gateway with WireGuard and dnsmasq.

set -e

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
}

# Function to install dependencies
install_deps() {
    echo "Installing necessary packages..."
    apt-get update
    apt-get install -y wireguard dnsmasq qrencode iptables
}

# Function to list network interfaces
get_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"
}

# Function to prompt for interface selection
select_interface() {
    local prompt_text="$1"
    local interfaces=$(get_interfaces)
    local chosen_iface=""

    echo "$prompt_text"
    select iface in $interfaces; do
        if [ -n "$iface" ]; then
            chosen_iface="$iface"
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
    echo "$chosen_iface"
}

# Function to prompt for config file path
get_wg_config() {
    while true; do
        read -e -p "Enter path to WireGuard peer config file (e.g., /home/pi/wg0.conf): " wg_conf_path
        if [ -f "$wg_conf_path" ]; then
            echo "$wg_conf_path"
            break
        else
            echo "File not found: $wg_conf_path. Please try again."
        fi
    done
}

# Function to prompt for IP range
get_ip_range() {
    read -e -p "Enter LAN IP range (CIDR format) [default: 10.10.10.0/24]: " lan_cidr
    if [ -z "$lan_cidr" ]; then
        lan_cidr="10.10.10.0/24"
    fi
    echo "$lan_cidr"
}

# Main setup logic
main() {
    check_root
    install_deps

    echo "--- Network Interface Configuration ---"
    WAN_IFACE=$(select_interface "Select the WAN interface (Internet connection):")
    echo "Selected WAN interface: $WAN_IFACE"

    LAN_IFACE=$(select_interface "Select the LAN interface (Access Point connection):")
    echo "Selected LAN interface: $LAN_IFACE"

    if [ "$WAN_IFACE" == "$LAN_IFACE" ]; then
        echo "Error: WAN and LAN interfaces cannot be the same."
        exit 1
    fi

    LAN_CIDR=$(get_ip_range)
    # Extract gateway IP (usually .1) and netmask
    LAN_IP=$(echo "$LAN_CIDR" | sed 's/\.0\/24$/.1/') # Simple assumption for /24, can be robustified
    
    # Robust IP calculation (requires ipcalc or similar, doing simple string manip for now for standard /24)
    # Assuming user inputs standard x.x.x.0/24
    SUBNET_BASE=$(echo "$LAN_CIDR" | cut -d'/' -f1)
    # First 3 octets
    PREFIX=$(echo "$SUBNET_BASE" | cut -d'.' -f1-3)
    LAN_GATEWAY="$PREFIX.1"
    DHCP_START="$PREFIX.10"
    DHCP_END="$PREFIX.250"

    echo "LAN Configuration:"
    echo "  CIDR: $LAN_CIDR"
    echo "  Gateway: $LAN_GATEWAY"
    echo "  DHCP Range: $DHCP_START - $DHCP_END"

    WG_CONF_SRC=$(get_wg_config)
    WG_CONF_DEST="/etc/wireguard/wg0.conf"

    echo "Copying WireGuard config..."
    cp "$WG_CONF_SRC" "$WG_CONF_DEST"
    chmod 600 "$WG_CONF_DEST"

    # Enable IP forwarding
    echo "Enabling IP forwarding..."
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sysctl -p

    # Configure static IP for LAN interface
    echo "Configuring static IP for $LAN_IFACE..."
    # Using dhcpcd.conf is common on Pi OS, but let's check if we should use creating a file in /etc/network/interfaces.d/ or systemd-networkd
    # Raspberry Pi OS (modern) often uses dhcpcd. Let's append to dhcpcd.conf if it exists, otherwise use nmcli or ip command? 
    # To be safe and persistent across reboots without conflicting with NetworkManager/dhcpcd too much:
    if [ -f /etc/dhcpcd.conf ]; then
        if grep -q "interface $LAN_IFACE" /etc/dhcpcd.conf; then
            echo "Warning: $LAN_IFACE configuration already exists in /etc/dhcpcd.conf. Please check manually."
        else
            echo "" >> /etc/dhcpcd.conf
            echo "interface $LAN_IFACE" >> /etc/dhcpcd.conf
            echo "static ip_address=$LAN_GATEWAY/24" >> /etc/dhcpcd.conf
            echo "nohook wpa_supplicant" >> /etc/dhcpcd.conf 
        fi
        # Restart dhcpcd to apply
        systemctl restart dhcpcd
    else
        echo "Warning: /etc/dhcpcd.conf not found. Configuring IP transiently (will be lost on reboot unless configured in your network manager)."
        ip addr add "$LAN_GATEWAY/24" dev "$LAN_IFACE"
    fi

    # Configure dnsmasq
    echo "Configuring dnsmasq..."
    mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null || true
    cat > /etc/dnsmasq.conf <<EOF
interface=$LAN_IFACE
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h
dhcp-option=option:dns-server,$LAN_GATEWAY
dhcp-option=option:router,$LAN_GATEWAY
bind-interfaces
EOF
    systemctl restart dnsmasq
    systemctl enable dnsmasq

    # Update WireGuard config with PostUp/PostDown for NAT
    echo "Adding NAT rules to WireGuard config..."
    
    # Check if [Interface] block exists
    if ! grep -q "\[Interface\]" "$WG_CONF_DEST"; then
        echo "Error: [Interface] block not found in $WG_CONF_DEST"
        exit 1
    fi

    # Add PostUp/PostDown rules
    # We use sed to insert after [Interface] line
    # Forwarding rules:
    # 1. Masquerade traffic leaving WAN_IFACE (if not going through VPN? Actually, usually we route traffic THROUGH VPN)
    # Wait, the request is "site-to-site connectivity". 
    # Usually this means:
    # - Traffic from LAN ($LAN_CIDR) going to Remote VPN Subnet -> goes via wg0
    # - Traffic from LAN ($LAN_CIDR) going to Internet -> goes via WAN_IFACE (Direct) OR via wg0 (VPN Tunnel)
    # Assuming user wants VPN connectivity to home network, and maybe internet via VPN?
    # Standard "Gateway" usually implies NATting LAN traffic out via wg0.
    
    # Let's assume split-tunnel or full-tunnel is defined in AllowedIPs of the peer config provided.
    # We just need to ensure packets from LAN can enter wg0.
    
    POST_UP="PostUp = iptables -A FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE"
    POST_DOWN="PostDown = iptables -D FORWARD -i $LAN_IFACE -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -o $LAN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE"

    # Also need to allow LAN to access Internet if NOT going via VPN? 
    # If AllowedIPs=0.0.0.0/0, everything goes wg0.
    # If AllowedIPs=192.168.1.0/24 (Home), then other traffic goes via WAN.
    # We should also add MASQUERADE for WAN_IFACE just in case they want local internet break-out for non-VPN traffic.
    
    POST_UP_WAN="; iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE"
    POST_DOWN_WAN="; iptables -t nat -D POSTROUTING -o $WAN_IFACE -j MASQUERADE"
    
    # Combining them
    FULL_POST_UP="${POST_UP}${POST_UP_WAN}"
    FULL_POST_DOWN="${POST_DOWN}${POST_DOWN_WAN}"

    # Insert into config
    # We use a temporary file to avoid complex sed escaping issues with multiple lines
    awk -v up="$FULL_POST_UP" -v down="$FULL_POST_DOWN" '/\[Interface\]/ { print; print up; print down; next } 1' "$WG_CONF_DEST" > "${WG_CONF_DEST}.tmp" && mv "${WG_CONF_DEST}.tmp" "$WG_CONF_DEST"

    echo "Starting WireGuard..."
    wg-quick up wg0
    systemctl enable wg-quick@wg0

    echo "Setup Complete!"
    echo "WAN: $WAN_IFACE"
    echo "LAN: $LAN_IFACE ($LAN_GATEWAY)"
    echo "VPN: wg0"
}

main

