# netanalytics-mcp

MCP (Model Context Protocol) server for the Network Analytics Toolkit. Exposes network discovery, scanning, traffic analysis, topology mapping, and security assessment tools for AI assistants.

## Installation

```bash
# From the project root
./scripts/install-mcp.sh

# Or manually with uv
uv sync
uv pip install -e ./mcp/netanalytics-mcp
```

## Usage

### With Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "netanalytics": {
      "command": "uv",
      "args": ["run", "python", "-m", "netanalytics_mcp.server"],
      "cwd": "/path/to/claude-code-network-analytics"
    }
  }
}
```

### Testing

```bash
# Interactive testing with FastMCP
uv run fastmcp dev netanalytics_mcp/server.py

# Run server directly
uv run python -m netanalytics_mcp.server
```

## Available Tools

### Discovery
- **discover_hosts** - Discover live hosts via ARP or ICMP (requires root)
- **scan_ports** - Scan ports on a target (SYN requires root)
- **detect_service_versions** - Detect services on open ports

### Traffic Analysis
- **capture_traffic** - Capture packets on interface (requires root)
- **analyze_pcap_file** - Analyze pcap file statistics
- **extract_dns_queries** - Extract DNS from pcap
- **extract_http_requests** - Extract HTTP from pcap

### Topology
- **build_network_topology** - Build network graph from scan or pcap
- **calculate_topology_metrics** - Calculate centrality, clustering
- **export_topology** - Export to graphml, gexf, json, or png

### Security
- **run_security_assessment** - Run basic or full assessment
- **check_target_vulnerabilities** - Check for common vulns
- **analyze_security_risks** - Analyze risk from findings

### Reporting
- **create_network_report** - Generate HTML/MD/JSON report
- **list_network_interfaces** - List available interfaces
- **get_results_directory** - Get results dir info

## Resources

- `netanalytics://config` - Current configuration
- `netanalytics://interfaces` - Network interfaces
- `netanalytics://results` - List result files
- `netanalytics://results/{filename}` - Get specific result

## Root Privileges

Operations requiring root:
- ARP/ICMP scanning
- SYN port scanning
- Packet capture

To run with elevated privileges:
```bash
sudo uv run python -m netanalytics_mcp.server
```

## Safety

- Only scan networks you own or have authorization to test
- External IP targets trigger warnings
- Rate limiting enabled by default
