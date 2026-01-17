"""Protocol-specific extraction and analysis."""

from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.all import DNS, IP, TCP, Raw, PcapReader

from ..core.exceptions import CaptureError


@dataclass
class HTTPRequest:
    """Extracted HTTP request."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    method: str
    uri: str
    host: str | None
    user_agent: str | None
    content_type: str | None

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "method": self.method,
            "uri": self.uri,
            "host": self.host,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
        }


@dataclass
class DNSQuery:
    """Extracted DNS query."""

    src_ip: str
    dst_ip: str
    query_name: str
    query_type: str
    answers: list[str]

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "query_name": self.query_name,
            "query_type": self.query_type,
            "answers": self.answers,
        }


@dataclass
class TCPStream:
    """Reconstructed TCP stream."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: int
    bytes_sent: int
    bytes_recv: int
    data_preview: str | None

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packets": self.packets,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "data_preview": self.data_preview,
        }


def extract_http(pcap_file: str) -> list[HTTPRequest]:
    """
    Extract HTTP requests from pcap file.

    Args:
        pcap_file: Path to pcap file

    Returns:
        List of HTTP requests
    """
    if not Path(pcap_file).exists():
        raise CaptureError(f"Pcap file not found: {pcap_file}")

    requests = []

    try:
        with closing(PcapReader(pcap_file)) as reader:
            for packet in reader:
                if not (packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP)):
                    continue

                tcp = packet.getlayer(TCP)
                ip = packet.getlayer(IP)
                raw = packet.getlayer(Raw)

                if tcp is None or ip is None or raw is None:
                    continue

                if tcp.dport not in (80, 8080) and tcp.sport not in (80, 8080):
                    continue

                try:
                    payload = raw.load.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                # Check if it's an HTTP request
                http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
                if not any(payload.startswith(m) for m in http_methods):
                    continue

                lines = payload.split("\r\n")
                if not lines:
                    continue

                # Parse request line
                request_line = lines[0].split(" ")
                if len(request_line) < 2:
                    continue

                method = request_line[0]
                uri = request_line[1]

                # Parse headers
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        headers[key.lower()] = value

                requests.append(
                    HTTPRequest(
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        src_port=tcp.sport,
                        dst_port=tcp.dport,
                        method=method,
                        uri=uri,
                        host=headers.get("host"),
                        user_agent=headers.get("user-agent"),
                        content_type=headers.get("content-type"),
                    )
                )
    except Exception as e:
        raise CaptureError(f"Failed to read pcap file: {pcap_file}", str(e)) from e

    return requests


def extract_dns(pcap_file: str) -> list[DNSQuery]:
    """
    Extract DNS queries and responses from pcap file.

    Args:
        pcap_file: Path to pcap file

    Returns:
        List of DNS queries
    """
    if not Path(pcap_file).exists():
        raise CaptureError(f"Pcap file not found: {pcap_file}")

    queries = []
    dns_cache = {}  # Track queries to match with responses

    # DNS query types
    dns_types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    try:
        with closing(PcapReader(pcap_file)) as reader:
            for packet in reader:
                if not packet.haslayer(DNS) or not packet.haslayer(IP):
                    continue

                dns = packet.getlayer(DNS)
                ip = packet.getlayer(IP)

                if dns is None or ip is None:
                    continue

                # DNS Query
                if dns.qr == 0 and dns.qd:
                    qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                    qtype = dns_types.get(dns.qd.qtype, str(dns.qd.qtype))

                    # Store query for later matching
                    dns_cache[dns.id] = {
                        "src_ip": ip.src,
                        "dst_ip": ip.dst,
                        "query_name": qname.rstrip("."),
                        "query_type": qtype,
                    }

                # DNS Response
                elif dns.qr == 1 and dns.id in dns_cache:
                    query_info = dns_cache[dns.id]
                    answers = []

                    # Extract answers
                    for i in range(dns.ancount):
                        try:
                            rr = dns.an[i]
                            if hasattr(rr, "rdata"):
                                rdata = rr.rdata
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode("utf-8", errors="ignore")
                                answers.append(str(rdata))
                        except Exception:
                            pass

                    queries.append(
                        DNSQuery(
                            src_ip=query_info["src_ip"],
                            dst_ip=query_info["dst_ip"],
                            query_name=query_info["query_name"],
                            query_type=query_info["query_type"],
                            answers=answers,
                        )
                    )
    except Exception as e:
        raise CaptureError(f"Failed to read pcap file: {pcap_file}", str(e)) from e

    return queries


def extract_tcp_streams(pcap_file: str, max_streams: int = 100) -> list[TCPStream]:
    """
    Extract TCP stream information from pcap file.

    Args:
        pcap_file: Path to pcap file
        max_streams: Maximum number of streams to return

    Returns:
        List of TCP streams
    """
    if not Path(pcap_file).exists():
        raise CaptureError(f"Pcap file not found: {pcap_file}")

    streams: defaultdict[tuple[str, int, str, int], dict[str, Any]] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes_fwd": 0,
            "bytes_rev": 0,
            "data": b"",
        }
    )

    try:
        with closing(PcapReader(pcap_file)) as reader:
            for packet in reader:
                if not packet.haslayer(TCP) or not packet.haslayer(IP):
                    continue

                ip = packet.getlayer(IP)
                tcp = packet.getlayer(TCP)

                if ip is None or tcp is None:
                    continue

                # Create stream key (normalized)
                endpoints = sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)])
                stream_key = (endpoints[0][0], endpoints[0][1], endpoints[1][0], endpoints[1][1])

                streams[stream_key]["packets"] += 1

                # Track bytes
                raw = packet.getlayer(Raw) if packet.haslayer(Raw) else None
                payload_len = len(raw.load) if raw is not None else 0
                if (ip.src, tcp.sport) == endpoints[0]:
                    streams[stream_key]["bytes_fwd"] += payload_len
                else:
                    streams[stream_key]["bytes_rev"] += payload_len

                # Capture some data for preview
                if raw is not None and len(streams[stream_key]["data"]) < 500:
                    streams[stream_key]["data"] += raw.load[:100]
    except Exception as e:
        raise CaptureError(f"Failed to read pcap file: {pcap_file}", str(e)) from e

    # Convert to TCPStream objects
    result = []
    for key, data in sorted(streams.items(), key=lambda x: -x[1]["packets"])[:max_streams]:
        data_preview = None
        if data["data"]:
            try:
                data_preview = data["data"][:200].decode("utf-8", errors="ignore")
                # Clean up non-printable characters
                data_preview = "".join(
                    c if c.isprintable() or c in "\n\r\t" else "."
                    for c in data_preview
                )
            except Exception:
                data_preview = data["data"][:200].hex()

        result.append(
            TCPStream(
                src_ip=key[0],
                src_port=key[1],
                dst_ip=key[2],
                dst_port=key[3],
                packets=data["packets"],
                bytes_sent=data["bytes_fwd"],
                bytes_recv=data["bytes_rev"],
                data_preview=data_preview,
            )
        )

    return result
