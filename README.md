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

## Prerequisites

Some features require elevated privileges and external tools:

- Root/sudo required for: ARP/ICMP discovery, SYN scans, packet capture.
- External tools:
  - `nmap` for advanced scanning (via python-nmap)
  - `tshark` or `tcpdump` for deeper packet inspection workflows

Install hints:

- macOS (Homebrew):
  - `brew install nmap wireshark`
  - `brew install tcpdump` (usually preinstalled)
- Ubuntu/Debian:
  - `sudo apt install nmap tshark tcpdump`
- Fedora:
  - `sudo dnf install nmap wireshark-cli tcpdump`

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

## Configuration

The CLI reads configuration from `.netanalytics.json` in the current working
directory by default. You can override the path with `NETANALYTICS_CONFIG`.

Example:

```bash
export NETANALYTICS_CONFIG=/path/to/netanalytics.json
```

Key settings include `results_dir`, scan timeouts/rate limits, capture defaults,
and topology visualization options. See `src/netanalytics/core/config.py` for
the full schema.

## Utilities

The `scripts/` directory includes helper utilities:

- `scripts/doctor.py`: environment checks (Python version, deps, external tools).
  - Example: `python scripts/doctor.py`
- `scripts/sample-data.py`: generate sample JSON outputs for demos/tests.
  - Example: `python scripts/sample-data.py --target 192.168.1.1`
- `scripts/bench.py`: benchmark scan throughput and latency.
  - Example: `python scripts/bench.py --target 127.0.0.1 --ports 1-1024`
- `scripts/report-batch.py`: batch report generation for multiple targets.
  - Example: `python scripts/report-batch.py --targets 192.168.1.1,192.168.1.2 --format html`
- `scripts/update-oui.py`: download and cache OUI vendor list.
  - Example: `python scripts/update-oui.py --output results/oui_vendors.json`
- `scripts/pcap-summarize.py`: quick pcap summary without full report.
  - Example: `python scripts/pcap-summarize.py capture.pcap --protocol dns`

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
