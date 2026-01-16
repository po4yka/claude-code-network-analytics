# Network Scan Command

Scan a network or host for open ports and services.

## Usage

```
/network-scan <target> [options]
```

## Arguments

- `target` (required): IP address, hostname, or CIDR network (e.g., `192.168.1.1` or `192.168.1.0/24`)

## Options

- `--ports, -p`: Port range to scan (default: `1-1000`)
- `--type, -t`: Scan type - `syn` (requires root) or `connect` (default: `connect`)
- `--fast`: Disable rate limiting for faster scans
- `--services`: Detect service versions on open ports
- `--output, -o`: Save results to file (JSON)

## Examples

```bash
# Basic port scan
/network-scan 192.168.1.1

# Scan specific ports
/network-scan 192.168.1.1 --ports 22,80,443,8080

# Full port range scan
/network-scan 192.168.1.1 --ports 1-65535 --fast

# Network discovery with ARP
/network-scan 192.168.1.0/24

# Service detection
/network-scan 192.168.1.1 --services
```

## What This Command Does

1. **Host Discovery**: For network ranges, first discovers live hosts using ARP (requires root) or ICMP
2. **Port Scanning**: Scans specified ports using TCP connect or SYN scan
3. **Service Detection**: Optionally identifies running services and versions
4. **Results Display**: Shows open ports, services, and response times

## Execution

When you invoke this command, I will:

1. Parse the target and determine scan type (single host vs network)
2. Run appropriate discovery methods
3. Execute port scan with specified options
4. Display results in a formatted table
5. Optionally save results to JSON

## Requirements

- For SYN scans and ARP discovery: root/sudo privileges
- For connect scans: no special privileges required
- Python package `netanalytics` must be installed

## Security Note

Only scan networks and systems you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.
