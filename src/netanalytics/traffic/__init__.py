"""Traffic analysis module - packet capture, protocol analysis, statistics."""

from .capture import capture_packets, PacketCapture
from .analyzer import analyze_pcap, ProtocolAnalyzer, TrafficStats
from .protocols import extract_http, extract_dns, extract_tcp_streams

__all__ = [
    "capture_packets",
    "PacketCapture",
    "analyze_pcap",
    "ProtocolAnalyzer",
    "TrafficStats",
    "extract_http",
    "extract_dns",
    "extract_tcp_streams",
]
