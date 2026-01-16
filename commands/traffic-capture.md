# Traffic Capture Command

Capture and analyze network traffic.

## Usage

```
/traffic-capture [interface] [options]
```

## Arguments

- `interface` (optional): Network interface to capture on (auto-detected if omitted)

## Options

- `--count, -c`: Number of packets to capture (default: 100)
- `--timeout, -t`: Capture timeout in seconds (default: 60)
- `--filter, -f`: BPF filter expression (e.g., `tcp port 80`)
- `--output, -o`: Save capture to pcap file
- `--analyze`: Analyze captured traffic immediately
- `--protocol`: Filter analysis by protocol (tcp, udp, http, dns)

## Examples

```bash
# Capture 100 packets on default interface
/traffic-capture

# Capture on specific interface with filter
/traffic-capture en0 --filter "tcp port 443" --count 200

# Capture and save to file
/traffic-capture eth0 --output capture.pcap --count 1000

# Capture and analyze HTTP traffic
/traffic-capture --filter "tcp port 80" --analyze --protocol http

# Analyze existing pcap file
/traffic-capture --analyze capture.pcap
```

## BPF Filter Examples

- `tcp`: All TCP traffic
- `udp`: All UDP traffic
- `port 80`: HTTP traffic
- `host 192.168.1.1`: Traffic to/from specific host
- `net 192.168.1.0/24`: Traffic within network
- `tcp and port 22`: SSH traffic
- `not port 53`: Exclude DNS traffic

## What This Command Does

1. **Interface Selection**: Lists available interfaces or uses specified one
2. **Packet Capture**: Captures packets with Scapy based on filters
3. **Real-time Display**: Shows packet summary as captured
4. **Analysis**: Provides protocol statistics, top talkers, conversations
5. **Export**: Saves to pcap for later analysis with Wireshark

## Analysis Output

- Total packets and bytes
- Protocol distribution
- Top source/destination IPs
- Top ports
- TCP flags distribution
- Network conversations

## Execution

When you invoke this command, I will:

1. List available interfaces if not specified
2. Start packet capture with provided parameters
3. Display capture progress
4. Show summary statistics
5. Optionally perform deep analysis
6. Save pcap file if requested

## Requirements

- Root/sudo privileges (packet capture requires elevated permissions)
- Scapy library
- For advanced analysis: pyshark/tshark
