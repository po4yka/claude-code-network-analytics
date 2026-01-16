"""Traffic analysis and statistics."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from scapy.all import DNS, ICMP, IP, TCP, UDP, rdpcap

from ..core.exceptions import CaptureError


@dataclass
class TrafficStats:
    """Traffic statistics from packet analysis."""

    total_packets: int
    total_bytes: int
    duration_seconds: float
    protocols: dict[str, int]
    top_sources: list[tuple[str, int]]
    top_destinations: list[tuple[str, int]]
    top_ports: list[tuple[int, int]]
    packets_per_second: float
    bytes_per_second: float
    tcp_flags: dict[str, int]
    conversations: list[dict]

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": round(self.duration_seconds, 2),
            "protocols": self.protocols,
            "top_sources": [{"ip": ip, "count": c} for ip, c in self.top_sources],
            "top_destinations": [{"ip": ip, "count": c} for ip, c in self.top_destinations],
            "top_ports": [{"port": p, "count": c} for p, c in self.top_ports],
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "tcp_flags": self.tcp_flags,
            "conversations": self.conversations,
        }

    def __str__(self) -> str:
        lines = [
            f"Total Packets: {self.total_packets}",
            f"Total Bytes: {self.total_bytes:,}",
            f"Duration: {self.duration_seconds:.2f}s",
            f"Rate: {self.packets_per_second:.2f} pps, {self.bytes_per_second:.2f} Bps",
            "",
            "Protocols:",
        ]
        for proto, count in sorted(self.protocols.items(), key=lambda x: -x[1]):
            lines.append(f"  {proto}: {count}")

        lines.append("\nTop Sources:")
        for ip, count in self.top_sources[:5]:
            lines.append(f"  {ip}: {count}")

        lines.append("\nTop Destinations:")
        for ip, count in self.top_destinations[:5]:
            lines.append(f"  {ip}: {count}")

        lines.append("\nTop Ports:")
        for port, count in self.top_ports[:5]:
            lines.append(f"  {port}: {count}")

        return "\n".join(lines)


class ProtocolAnalyzer:
    """Analyze network traffic protocols."""

    def __init__(self):
        self.packets = []
        self.protocols = Counter()
        self.sources = Counter()
        self.destinations = Counter()
        self.ports = Counter()
        self.tcp_flags = Counter()
        self.conversations = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None

    def add_packet(self, packet) -> None:
        """Add a packet to analysis."""
        self.packets.append(packet)
        self.total_bytes += len(packet)

        # Track time
        pkt_time = float(packet.time)
        if self.start_time is None or pkt_time < self.start_time:
            self.start_time = pkt_time
        if self.end_time is None or pkt_time > self.end_time:
            self.end_time = pkt_time

        # Protocol analysis
        if packet.haslayer(TCP):
            self.protocols["TCP"] += 1
            tcp = packet.getlayer(TCP)
            self.ports[tcp.sport] += 1
            self.ports[tcp.dport] += 1

            # Track TCP flags
            flags = tcp.flags
            if flags & 0x02:
                self.tcp_flags["SYN"] += 1
            if flags & 0x10:
                self.tcp_flags["ACK"] += 1
            if flags & 0x01:
                self.tcp_flags["FIN"] += 1
            if flags & 0x04:
                self.tcp_flags["RST"] += 1
            if flags & 0x08:
                self.tcp_flags["PSH"] += 1

        elif packet.haslayer(UDP):
            self.protocols["UDP"] += 1
            udp = packet.getlayer(UDP)
            self.ports[udp.sport] += 1
            self.ports[udp.dport] += 1

        elif packet.haslayer(ICMP):
            self.protocols["ICMP"] += 1

        # IP analysis
        if packet.haslayer(IP):
            ip = packet.getlayer(IP)
            self.sources[ip.src] += 1
            self.destinations[ip.dst] += 1

            # Track conversation
            conv_key = tuple(sorted([ip.src, ip.dst]))
            self.conversations[conv_key]["packets"] += 1
            self.conversations[conv_key]["bytes"] += len(packet)

        # DNS analysis
        if packet.haslayer(DNS):
            self.protocols["DNS"] += 1

    def get_stats(self) -> TrafficStats:
        """Get traffic statistics."""
        duration = (self.end_time - self.start_time) if self.start_time and self.end_time else 0.0
        if duration == 0:
            duration = 0.001  # Avoid division by zero

        conversations_list = [
            {
                "endpoints": list(k),
                "packets": v["packets"],
                "bytes": v["bytes"],
            }
            for k, v in sorted(self.conversations.items(), key=lambda x: -x[1]["packets"])[:10]
        ]

        return TrafficStats(
            total_packets=len(self.packets),
            total_bytes=self.total_bytes,
            duration_seconds=duration,
            protocols=dict(self.protocols),
            top_sources=self.sources.most_common(10),
            top_destinations=self.destinations.most_common(10),
            top_ports=self.ports.most_common(10),
            packets_per_second=len(self.packets) / duration,
            bytes_per_second=self.total_bytes / duration,
            tcp_flags=dict(self.tcp_flags),
            conversations=conversations_list,
        )


def analyze_pcap(
    pcap_file: str,
    protocol_filter: str = "all",
) -> TrafficStats:
    """
    Analyze a pcap file and return statistics.

    Args:
        pcap_file: Path to pcap file
        protocol_filter: Filter by protocol ("all", "tcp", "udp", "http", "dns")

    Returns:
        TrafficStats with analysis results
    """
    if not Path(pcap_file).exists():
        raise CaptureError(f"Pcap file not found: {pcap_file}")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        raise CaptureError(f"Failed to read pcap file: {pcap_file}", str(e)) from e

    analyzer = ProtocolAnalyzer()

    for packet in packets:
        # Apply protocol filter
        if protocol_filter == "tcp" and not packet.haslayer(TCP):
            continue
        if protocol_filter == "udp" and not packet.haslayer(UDP):
            continue
        if protocol_filter == "http":
            if not packet.haslayer(TCP):
                continue
            http_ports = (80, 443)
            if packet.sport not in http_ports and packet.dport not in http_ports:
                continue
        if protocol_filter == "dns" and not packet.haslayer(DNS):
            continue

        analyzer.add_packet(packet)

    return analyzer.get_stats()
