# Traffic Analysis Skill

Guidance for network traffic capture and analysis.

## Capture Techniques

### Live Capture
```bash
# Capture on interface
netanalytics capture en0 --count 1000

# With BPF filter
netanalytics capture en0 --filter "tcp port 80" --count 500

# Save to file
netanalytics capture en0 --output capture.pcap
```

### Pcap Analysis
```bash
# General analysis
netanalytics analyze capture.pcap

# Protocol-specific
netanalytics analyze capture.pcap --protocol http
netanalytics analyze capture.pcap --protocol dns
```

## BPF Filter Syntax

### Basic Filters
```
host 192.168.1.1          # Traffic to/from host
net 192.168.1.0/24        # Traffic within network
port 80                    # Traffic on port 80
portrange 1-1024          # Port range
```

### Protocol Filters
```
tcp                        # TCP traffic only
udp                        # UDP traffic only
icmp                       # ICMP traffic only
arp                        # ARP traffic only
```

### Compound Filters
```
tcp and port 80           # TCP HTTP
tcp and port 443          # TCP HTTPS
udp and port 53           # UDP DNS
host 192.168.1.1 and tcp  # TCP to/from host
```

### Direction Filters
```
src host 192.168.1.1      # Source is host
dst host 192.168.1.1      # Destination is host
src port 80               # Source port 80
dst port 80               # Destination port 80
```

### Negation
```
not port 22               # Exclude SSH
not host 192.168.1.1      # Exclude host
tcp and not port 443      # TCP except HTTPS
```

## Protocol Analysis

### HTTP Traffic
- Look for: Unencrypted credentials, sensitive data
- Extract: URLs, User-Agents, POST data
- Filter: `tcp port 80`

### DNS Traffic
- Look for: Unusual queries, tunneling
- Extract: Queried domains, response IPs
- Filter: `udp port 53`

### TLS/SSL Traffic
- Look for: Weak ciphers, expired certs
- Extract: SNI (Server Name Indication)
- Filter: `tcp port 443`

### SMB Traffic
- Look for: Lateral movement, file transfers
- Extract: Share access, user accounts
- Filter: `tcp port 445`

## Traffic Patterns

### Normal Patterns
- Regular DNS queries to known servers
- HTTPS to expected destinations
- NTP synchronization
- DHCP renewals

### Suspicious Patterns
- DNS queries to unusual TLDs
- Large outbound transfers
- Connections to known-bad IPs
- Beacon-like periodic traffic
- Unusual port usage

### Attack Indicators
- Port scanning (many SYNs, few ACKs)
- SYN floods (many SYNs to one port)
- ARP spoofing (multiple MACs for one IP)
- DNS amplification (large responses)

## Analysis Metrics

### Volume Metrics
- Packets per second
- Bytes per second
- Protocol distribution

### Connection Metrics
- Active connections
- Connection duration
- Retransmission rate

### Top-N Analysis
- Top talkers (source IPs)
- Top destinations
- Top ports
- Top protocols

## Best Practices

1. **Capture enough**: Short captures miss patterns
2. **Filter early**: Reduce noise at capture time
3. **Save originals**: Keep unfiltered pcaps
4. **Timestamp everything**: Enable precise timestamps
5. **Know your baseline**: Understand normal traffic
6. **Use display filters**: Analyze subsets of data

## Tools Integration

### Wireshark
```bash
# Open pcap in Wireshark
wireshark capture.pcap

# Export from tshark
tshark -r capture.pcap -T fields -e ip.src -e ip.dst
```

### tcpdump
```bash
# Quick capture
tcpdump -i en0 -w capture.pcap

# Read with filter
tcpdump -r capture.pcap 'tcp port 80'
```

## References

- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- [SANS Traffic Analysis](https://www.sans.org/blog/traffic-analysis-with-wireshark/)
