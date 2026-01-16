# Network Analytics Toolkit

A comprehensive Python toolkit for network discovery, scanning, traffic analysis, topology mapping, and security assessment.

## Features

- **Network Discovery**: ARP and ICMP host discovery
- **Port Scanning**: SYN and connect scans with service detection
- **Traffic Analysis**: Packet capture and pcap analysis
- **Topology Mapping**: NetworkX-based topology visualization
- **Security Assessment**: Vulnerability checks and risk analysis
- **MCP Server**: AI-native integration via Model Context Protocol

## Installation

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

## Quick Start

```bash
# Discover hosts on local network (requires root)
sudo uv run netanalytics discover 192.168.1.0/24 --method arp

# Port scan
uv run netanalytics scan 192.168.1.1 --ports 22,80,443

# Capture traffic (requires root)
sudo uv run netanalytics capture en0 --count 100 -o capture.pcap

# Analyze pcap
uv run netanalytics analyze capture.pcap --protocol http

# Security assessment
uv run netanalytics security 192.168.1.1 --level basic

# Generate report
uv run netanalytics report 192.168.1.1 --format html
```

## MCP Server

The toolkit includes an MCP server for AI integration:

```bash
# Install MCP server
./scripts/install-mcp.sh

# Test interactively
uv run fastmcp dev mcp/netanalytics-mcp/netanalytics_mcp/server.py
```

See [mcp/netanalytics-mcp/README.md](mcp/netanalytics-mcp/README.md) for details.

## Requirements

- Python 3.11+
- Root/sudo for: ARP/ICMP scanning, SYN scans, packet capture

## License

MIT
