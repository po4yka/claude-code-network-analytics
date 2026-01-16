# Network Scanning Skill

Guidance for network scanning techniques and best practices.

## Scan Types

### TCP Connect Scan
- Completes full 3-way handshake
- No special privileges required
- More detectable but reliable
- Use for: Initial reconnaissance, stealth not required

### TCP SYN Scan (Half-open)
- Sends SYN, analyzes response
- Requires root/admin privileges
- Faster and less detectable
- Use for: Stealthy scanning, large networks

### ARP Scan
- Layer 2 discovery on local network
- Most accurate for local subnets
- Reveals MAC addresses and vendors
- Use for: LAN discovery, asset inventory

### ICMP Scan (Ping)
- Layer 3 connectivity test
- May be blocked by firewalls
- Good for initial host discovery
- Use for: Quick alive check, network mapping

## Port Ranges

### Well-Known Ports (1-1023)
System services, require root to bind
- 21: FTP
- 22: SSH
- 23: Telnet
- 25: SMTP
- 53: DNS
- 80: HTTP
- 443: HTTPS

### Registered Ports (1024-49151)
Application services
- 3306: MySQL
- 5432: PostgreSQL
- 8080: HTTP Proxy
- 27017: MongoDB

### Dynamic Ports (49152-65535)
Ephemeral/client ports

## Scan Strategies

### Quick Scan
```bash
netanalytics scan <target> --ports 21,22,23,25,80,443,3389
```

### Top 1000 Ports
```bash
netanalytics scan <target> --ports 1-1000
```

### Full Scan
```bash
netanalytics scan <target> --ports 1-65535 --fast
```

### Service-Focused
```bash
# Web services
netanalytics scan <target> --ports 80,443,8080,8443

# Databases
netanalytics scan <target> --ports 3306,5432,1433,27017,6379

# Remote access
netanalytics scan <target> --ports 22,23,3389,5900
```

## Rate Limiting

### Conservative (Default)
- 100 packets/second
- Suitable for production networks
- Minimizes detection risk

### Fast Mode
- No rate limiting
- Use for isolated test environments
- May trigger IDS/IPS alerts

## Response Interpretation

### Port States
- **Open**: Service accepting connections
- **Closed**: No service, host responds with RST
- **Filtered**: No response (firewall blocking)
- **Open|Filtered**: No response, could be either

### Common Responses
- SYN-ACK: Port open
- RST-ACK: Port closed
- No response: Filtered or host down
- ICMP unreachable: Administratively filtered

## Best Practices

1. **Start small**: Quick scan before full scan
2. **Use filters**: Target specific services
3. **Document scope**: Know what you're authorized to scan
4. **Mind the noise**: Rate limit on production networks
5. **Verify results**: Rerun uncertain findings
6. **Save output**: Keep records for analysis

## References

- [Nmap Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
- [IANA Port Assignments](https://www.iana.org/assignments/service-names-port-numbers/)
- [Common Ports Cheat Sheet](https://packetlife.net/media/library/23/common_ports.pdf)
