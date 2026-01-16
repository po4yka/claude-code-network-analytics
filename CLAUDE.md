# Network Analytics Toolkit - Claude Code Configuration

## Project Overview

Network Analytics Toolkit for discovery, scanning, traffic analysis, topology mapping, and security assessment.

## Available Commands

| Command | Description |
|---------|-------------|
| `/network-scan <target>` | Scan hosts and ports |
| `/topology-map <network>` | Visualize network graph |
| `/traffic-capture [interface]` | Capture/analyze packets |
| `/security-check <target>` | Vulnerability assessment |
| `/net-report <target>` | Generate full report |

## Available Agents

| Agent | Use Case |
|-------|----------|
| `network-analyst` | Complex investigations, anomaly detection |
| `security-auditor` | Penetration prep, risk analysis |

## Development Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
# Install dependencies
uv sync

# Run CLI
uv run netanalytics --help
```

## CLI Usage

```bash
# Discovery
uv run netanalytics discover <network> --method arp|icmp

# Port scanning
uv run netanalytics scan <target> --ports <range> --type syn|connect

# Traffic capture (requires root)
sudo uv run netanalytics capture <interface> --count 100 --filter <bpf>

# Traffic analysis
uv run netanalytics analyze <pcap-file> --protocol http|dns|all

# Topology mapping
sudo uv run netanalytics topology <network> --output graph.png

# Security assessment
uv run netanalytics security <target> --level basic|full

# Report generation
uv run netanalytics report <target> --format html|md|json
```

## Common Patterns

### Network Discovery
```bash
# Local network discovery (requires root)
sudo uv run netanalytics discover 192.168.1.0/24 --method arp

# Quick port scan
uv run netanalytics scan 192.168.1.1 --ports 22,80,443,3306
```

### Security Assessment
```bash
# Basic security check
uv run netanalytics security 192.168.1.1

# Full assessment with report
uv run netanalytics security 192.168.1.1 --level full -o report.json
```

### Traffic Analysis
```bash
# Capture HTTP traffic
sudo uv run netanalytics capture en0 --filter "tcp port 80" --count 500 -o http.pcap

# Analyze captured traffic
uv run netanalytics analyze http.pcap --protocol http
```

## Permissions

Many operations require root/sudo privileges:
- ARP scanning
- ICMP scanning
- SYN scanning
- Packet capture

Connect scans and analysis work without root.

## Project Structure

```
src/netanalytics/
├── cli.py              # CLI entry point
├── core/               # Config, exceptions, utils
├── discovery/          # ARP/ICMP/port scanning
├── topology/           # NetworkX graphs
├── traffic/            # Packet capture/analysis
├── security/           # Vulnerability checks
├── wrappers/           # nmap, tshark, ncat
└── output/             # Reports, export

mcp/
├── netanalytics-mcp/   # Custom MCP server
│   ├── netanalytics_mcp/
│   │   ├── server.py   # Main MCP server
│   │   ├── tools/      # Tool implementations
│   │   └── resources/  # Resource providers
│   └── pyproject.toml
└── configs/            # MCP client configs
```

## MCP Server

The toolkit exposes an MCP server for AI-native integration.

### Installation

```bash
# Install custom MCP server
./scripts/install-mcp.sh

# Or with external servers (nmap, wiremcp, suricata)
./scripts/install-mcp.sh --all
```

### Available MCP Tools

| Tool | Description | Root |
|------|-------------|------|
| `discover_hosts` | ARP/ICMP host discovery | Yes |
| `scan_ports` | Port scanning (syn/connect) | syn: Yes |
| `detect_service_versions` | Service fingerprinting | No |
| `capture_traffic` | Packet capture | Yes |
| `analyze_pcap_file` | Analyze pcap files | No |
| `extract_dns_queries` | Extract DNS from pcap | No |
| `extract_http_requests` | Extract HTTP from pcap | No |
| `build_network_topology` | Build network graph | scan: Yes |
| `calculate_topology_metrics` | Graph metrics | No |
| `export_topology` | Export to graphml/gexf/json/png | No |
| `run_security_assessment` | Security assessment | No |
| `check_target_vulnerabilities` | Vulnerability checks | No |
| `analyze_security_risks` | Risk analysis | No |
| `create_network_report` | Generate reports | No |
| `list_network_interfaces` | List interfaces | No |

### MCP Resources

- `netanalytics://config` - Current configuration
- `netanalytics://interfaces` - Network interfaces
- `netanalytics://results` - Result files listing
- `netanalytics://results/{filename}` - Specific result file

### Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

### Testing MCP Server

```bash
# Interactive test
uv run fastmcp dev mcp/netanalytics-mcp/netanalytics_mcp/server.py

# Test specific tool
uv run python -c "from netanalytics_mcp.server import mcp; print(mcp.list_tools())"
```

## Safety Notes

- Only scan networks you own or have authorization for
- External IP scanning triggers a confirmation prompt
- Rate limiting is enabled by default (--fast to disable)
- Results are stored in `./results/` directory
