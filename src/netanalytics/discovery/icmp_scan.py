"""ICMP-based network discovery using Scapy."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Network
import socket

from scapy.all import IP, ICMP, sr1, sr, conf

from ..core.config import get_config
from ..core.exceptions import ScanError, PermissionError
from ..core.utils import is_root, validate_network, validate_ip, resolve_hostname


@dataclass
class ICMPResult:
    """Result of an ICMP ping for a single host."""

    ip: str
    is_alive: bool
    hostname: str | None
    ttl: int | None
    rtt: float | None  # Round-trip time in seconds
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "is_alive": self.is_alive,
            "hostname": self.hostname,
            "ttl": self.ttl,
            "rtt_ms": round(self.rtt * 1000, 2) if self.rtt else None,
            "timestamp": self.timestamp.isoformat(),
        }


def ping_host(ip: str, timeout: float = 2.0, count: int = 1) -> ICMPResult:
    """
    Ping a single host using ICMP echo request.

    Args:
        ip: Target IP address
        timeout: Timeout per ping in seconds
        count: Number of ping attempts

    Returns:
        ICMPResult with ping statistics
    """
    if not is_root():
        raise PermissionError("ICMP ping", "Requires root privileges")

    validate_ip(ip)
    conf.verb = 0

    timestamp = datetime.now()
    best_rtt = None
    ttl = None
    is_alive = False

    for _ in range(count):
        packet = IP(dst=ip) / ICMP()
        start = datetime.now()

        try:
            reply = sr1(packet, timeout=timeout, verbose=False)
        except Exception as e:
            continue

        if reply and reply.haslayer(ICMP):
            rtt = (datetime.now() - start).total_seconds()
            is_alive = True
            ttl = reply.ttl

            if best_rtt is None or rtt < best_rtt:
                best_rtt = rtt

    return ICMPResult(
        ip=ip,
        is_alive=is_alive,
        hostname=resolve_hostname(ip) if is_alive else None,
        ttl=ttl,
        rtt=best_rtt,
        timestamp=timestamp,
    )


def icmp_scan(
    network: str,
    timeout: float | None = None,
    rate_limit: int | None = None,
) -> list[ICMPResult]:
    """
    Perform ICMP scan on a network range.

    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        timeout: Timeout per host in seconds
        rate_limit: Max packets per second

    Returns:
        List of ICMPResult for all hosts (including non-responding)
    """
    if not is_root():
        raise PermissionError("ICMP scan", "Requires root privileges")

    config = get_config()
    timeout = timeout or config.scan.timeout
    rate_limit = rate_limit or config.scan.rate_limit

    net = validate_network(network)
    conf.verb = 0

    hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        return []

    # Build ICMP packets for all hosts
    packets = [IP(dst=host) / ICMP() for host in hosts]
    timestamp = datetime.now()

    try:
        inter = 1.0 / rate_limit if rate_limit and not config.fast_mode else 0
        answered, unanswered = sr(packets, timeout=timeout, inter=inter, verbose=False)
    except Exception as e:
        raise ScanError(f"ICMP scan failed for {network}", str(e))

    results = []

    # Process answered packets
    alive_ips = set()
    for sent, received in answered:
        if received.haslayer(ICMP):
            ip = received.src
            alive_ips.add(ip)
            results.append(
                ICMPResult(
                    ip=ip,
                    is_alive=True,
                    hostname=resolve_hostname(ip),
                    ttl=received.ttl,
                    rtt=None,  # Can't calculate individual RTT in batch mode
                    timestamp=timestamp,
                )
            )

    # Add unanswered hosts
    for packet in unanswered:
        ip = packet.dst
        if ip not in alive_ips:
            results.append(
                ICMPResult(
                    ip=ip,
                    is_alive=False,
                    hostname=None,
                    ttl=None,
                    rtt=None,
                    timestamp=timestamp,
                )
            )

    # Sort by IP address
    results.sort(key=lambda r: tuple(map(int, r.ip.split("."))))
    return results


def icmp_scan_alive_only(
    network: str,
    timeout: float | None = None,
    rate_limit: int | None = None,
) -> list[ICMPResult]:
    """
    Perform ICMP scan and return only alive hosts.

    Args:
        network: Network in CIDR notation
        timeout: Timeout per host in seconds
        rate_limit: Max packets per second

    Returns:
        List of ICMPResult for alive hosts only
    """
    results = icmp_scan(network, timeout, rate_limit)
    return [r for r in results if r.is_alive]
