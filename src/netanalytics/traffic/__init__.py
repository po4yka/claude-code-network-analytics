"""Traffic analysis module - packet capture, protocol analysis, statistics."""

from .analyzer import ProtocolAnalyzer, TrafficStats, analyze_pcap
from .capture import PacketCapture, capture_packets
from .protocols import extract_dns, extract_http, extract_tcp_streams

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
