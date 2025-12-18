# Remote Site-to-Site VPN Gateway

## Overview

This project configures a **Raspberry Pi 4** running **Raspberry Pi OS Lite** as a VPN gateway.

The primary goal is to create a **secure, site-to-site sub-network** that sits behind an existing, potentially unsecure or restricted subnet. By establishing an outbound **WireGuard** tunnel to a trusted home network, this setup provides a private, bidirectional extension of the home network into the remote location, bypassing local network restrictions.

## Constraints & Challenges

- **Host Device**: Raspberry Pi 4.
- **Network Access**: No administrative access to the underlying network infrastructure (router/ISP).
- **No Port Forwarding**: Cannot configure port forwarding; likely behind NAT/CGNAT.

## Goals

1.  **Secure Subnet**: Create a private subnet for devices at the remote location.
2.  **Site-to-Site Connectivity**: Establish a persistent VPN tunnel to the home network.
3.  **Bidirectional Access**: Ensure all devices on the remote subnet are reachable from the home network, and home network devices are reachable from the remote subnet.

## Architecture

The solution uses **WireGuard** for the VPN tunnel. Given the inability to open inbound ports at the remote site:
- The remote Pi initiates a persistent *outbound* WireGuard connection to the home network (which acts as the "server" or has a publicly accessible endpoint).
- `PersistentKeepalive` is used to maintain the NAT mapping.

## Network Topology

The Raspberry Pi acts as a router between the restricted on-site network and a new private subnet:

- **WAN (Internet)**: Connected via a **secondary network adapter** (e.g., USB Ethernet). This interface connects to the existing on-site network to access the internet.
- **LAN (Private Subnet)**: The **built-in Ethernet port** serves as the gateway for the secure subnet.
- **Access Point**: A wireless access point connects to the LAN port to provide Wi-Fi to local devices.

## Software Requirements

- **OS**: Raspberry Pi OS Lite (minimal, headless).
- **VPN**: WireGuard.

## Hardware Requirements

- Raspberry Pi 4
- Secondary Network Adapter (USB Ethernet)
- Wireless Access Point (AP)
- Ethernet cables

## Getting Started

*Documentation in progress.*
