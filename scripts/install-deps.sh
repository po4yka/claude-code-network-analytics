#!/bin/bash
# Install dependencies for Network Analytics Toolkit

set -e

echo "=== Network Analytics Toolkit - Dependency Installer ==="
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PKG_MANAGER="brew"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"
    PKG_MANAGER="apt"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
    PKG_MANAGER="yum"
else
    OS="unknown"
    PKG_MANAGER="unknown"
fi

echo "Detected OS: $OS"
echo "Package manager: $PKG_MANAGER"
echo ""

# Install system dependencies
echo "=== Installing System Dependencies ==="

if [[ "$PKG_MANAGER" == "brew" ]]; then
    echo "Installing via Homebrew..."
    brew install nmap wireshark libpcap

    # ncat is included with nmap
    echo "Note: ncat is included with nmap installation"

elif [[ "$PKG_MANAGER" == "apt" ]]; then
    echo "Installing via apt..."
    sudo apt update
    sudo apt install -y nmap tshark ncat libpcap-dev python3-dev

    # Allow non-root packet capture
    echo "Configuring packet capture permissions..."
    sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

elif [[ "$PKG_MANAGER" == "yum" ]]; then
    echo "Installing via yum..."
    sudo yum install -y nmap wireshark nmap-ncat libpcap-devel python3-devel

else
    echo "Unknown package manager. Please install manually:"
    echo "  - nmap"
    echo "  - wireshark/tshark"
    echo "  - ncat"
    echo "  - libpcap"
fi

echo ""
echo "=== Installing Python Dependencies ==="

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo "pip3 not found. Please install Python 3 and pip."
    exit 1
fi

# Install in development mode
echo "Installing netanalytics package..."
pip3 install -e ".[dev]"

echo ""
echo "=== Verifying Installation ==="

# Check commands
echo -n "nmap: "
if command -v nmap &> /dev/null; then
    echo "✓ $(nmap --version | head -1)"
else
    echo "✗ not found"
fi

echo -n "tshark: "
if command -v tshark &> /dev/null; then
    echo "✓ $(tshark --version | head -1)"
else
    echo "✗ not found"
fi

echo -n "ncat: "
if command -v ncat &> /dev/null; then
    echo "✓ found"
elif command -v nc &> /dev/null; then
    echo "✓ nc found (alternative)"
else
    echo "✗ not found"
fi

echo -n "netanalytics: "
if command -v netanalytics &> /dev/null; then
    echo "✓ $(netanalytics --version)"
else
    echo "✗ not found"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Usage:"
echo "  netanalytics --help"
echo "  netanalytics discover 192.168.1.0/24"
echo "  netanalytics scan 192.168.1.1 --ports 1-1000"
echo ""
echo "Note: Some operations require root/sudo privileges."
