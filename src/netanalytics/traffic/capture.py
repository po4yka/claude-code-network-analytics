"""Packet capture using Scapy."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Packet, rdpcap, sniff, wrpcap

from ..core.config import get_config
from ..core.exceptions import CaptureError, PermissionError
from ..core.utils import is_root


@dataclass
class CapturedPacket:
    """Information about a captured packet."""

    number: int
    timestamp: datetime
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    summary: str

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "summary": self.summary,
        }


def _get_protocol(packet: Packet) -> str:
    """Determine protocol from packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    elif packet.haslayer(IP):
        return "IP"
    elif packet.haslayer(Ether):
        return "Ethernet"
    return "Unknown"


def _packet_to_captured(packet: Packet, number: int) -> CapturedPacket:
    """Convert Scapy packet to CapturedPacket."""
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        src_port = udp_layer.sport
        dst_port = udp_layer.dport

    return CapturedPacket(
        number=number,
        timestamp=datetime.fromtimestamp(float(packet.time)),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=_get_protocol(packet),
        length=len(packet),
        summary=packet.summary(),
    )


def capture_packets(
    interface: str,
    count: int = 100,
    timeout: int | None = None,
    bpf_filter: str | None = None,
    output_file: str | None = None,
    callback: Callable[[CapturedPacket], None] | None = None,
) -> list[CapturedPacket]:
    """
    Capture network packets.

    Args:
        interface: Network interface to capture on
        count: Maximum number of packets to capture
        timeout: Capture timeout in seconds
        bpf_filter: Berkeley Packet Filter expression
        output_file: Path to save pcap file
        callback: Function to call for each captured packet

    Returns:
        List of captured packets
    """
    if not is_root():
        raise PermissionError("Packet capture", "Requires root privileges")

    config = get_config()
    timeout = timeout or config.capture.default_timeout

    captured: list[CapturedPacket] = []
    raw_packets: list[Packet] = []
    packet_num = 0

    def packet_handler(packet: Packet) -> None:
        nonlocal packet_num
        packet_num += 1
        raw_packets.append(packet)

        cap_packet = _packet_to_captured(packet, packet_num)
        captured.append(cap_packet)

        if callback:
            callback(cap_packet)

    try:
        sniff(
            iface=interface,
            count=count,
            timeout=timeout,
            filter=bpf_filter,
            prn=packet_handler,
            store=False,
        )
    except Exception as e:
        raise CaptureError(f"Capture failed on {interface}", str(e)) from e

    # Save to pcap file if requested
    if output_file and raw_packets:
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            wrpcap(output_file, raw_packets)
        except Exception as e:
            raise CaptureError(f"Failed to save pcap to {output_file}", str(e)) from e

    return captured


def read_pcap(pcap_file: str) -> list[CapturedPacket]:
    """
    Read packets from a pcap file.

    Args:
        pcap_file: Path to pcap file

    Returns:
        List of captured packets
    """
    if not Path(pcap_file).exists():
        raise CaptureError(f"Pcap file not found: {pcap_file}")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        raise CaptureError(f"Failed to read pcap file: {pcap_file}", str(e)) from e

    captured = []
    for i, packet in enumerate(packets):
        captured.append(_packet_to_captured(packet, i + 1))

    return captured


class PacketCapture:
    """Context manager for packet capture."""

    def __init__(
        self,
        interface: str,
        count: int = 100,
        timeout: int | None = None,
        bpf_filter: str | None = None,
        output_file: str | None = None,
    ):
        self.interface = interface
        self.count = count
        self.timeout = timeout
        self.bpf_filter = bpf_filter
        self.output_file = output_file
        self.packets: list[CapturedPacket] = []

    def __enter__(self) -> "PacketCapture":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def start(self) -> list[CapturedPacket]:
        """Start packet capture."""
        self.packets = capture_packets(
            interface=self.interface,
            count=self.count,
            timeout=self.timeout,
            bpf_filter=self.bpf_filter,
            output_file=self.output_file,
        )
        return self.packets
