#!/bin/bash
# Check if current user has required permissions for network operations

echo "=== Network Analytics - Permission Check ==="
echo ""

# Check if root
echo -n "Root privileges: "
if [[ $EUID -eq 0 ]]; then
    echo "✓ Running as root"
    ROOT_OK=true
else
    echo "✗ Not root (some features will be limited)"
    ROOT_OK=false
fi

# Check raw socket capability
echo -n "Raw socket access: "
if [[ "$ROOT_OK" == "true" ]]; then
    echo "✓ Available (root)"
elif getcap $(which python3) 2>/dev/null | grep -q cap_net_raw; then
    echo "✓ Available (capabilities set)"
else
    echo "✗ Not available"
    echo "   To enable without root, run:"
    echo "   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
fi

# Check packet capture
echo -n "Packet capture: "
if [[ "$ROOT_OK" == "true" ]]; then
    echo "✓ Available (root)"
elif groups | grep -qE "(wireshark|pcap)"; then
    echo "✓ Available (wireshark/pcap group)"
else
    echo "✗ May require root or group membership"
    echo "   To add yourself to wireshark group:"
    echo "   sudo usermod -aG wireshark $USER"
fi

# Check for nmap
echo -n "nmap: "
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -1)
    echo "✓ $NMAP_VERSION"
else
    echo "✗ Not installed"
fi

# Check for tshark
echo -n "tshark: "
if command -v tshark &> /dev/null; then
    TSHARK_VERSION=$(tshark --version 2>/dev/null | head -1)
    echo "✓ $TSHARK_VERSION"
else
    echo "✗ Not installed"
fi

# List available interfaces
echo ""
echo "=== Available Network Interfaces ==="
if command -v ip &> /dev/null; then
    ip -br link show
elif command -v ifconfig &> /dev/null; then
    ifconfig -l 2>/dev/null || ifconfig | grep -E "^[a-z]" | cut -d: -f1
else
    echo "Could not list interfaces"
fi

echo ""
echo "=== Feature Availability ==="
echo ""

if [[ "$ROOT_OK" == "true" ]]; then
    echo "✓ ARP scanning"
    echo "✓ ICMP scanning"
    echo "✓ SYN scanning"
    echo "✓ Packet capture"
    echo "✓ All features available"
else
    echo "✓ TCP connect scanning (no root needed)"
    echo "✓ Service detection (no root needed)"
    echo "✗ ARP scanning (requires root)"
    echo "✗ ICMP scanning (requires root)"
    echo "✗ SYN scanning (requires root)"
    echo "? Packet capture (may require root or group)"
    echo ""
    echo "To run with full capabilities:"
    echo "  sudo netanalytics <command>"
fi

echo ""
