"""ARP-based network discovery using Scapy."""

from dataclasses import dataclass
from datetime import datetime

from scapy.all import ARP, Ether, conf, srp

from ..core.config import get_config
from ..core.exceptions import PermissionError, ScanError
from ..core.utils import (
    format_mac,
    get_oui_vendor,
    is_root,
    resolve_hostname,
    validate_network,
)


@dataclass
class ARPResult:
    """Result of an ARP scan for a single host."""

    ip: str
    mac: str
    hostname: str | None
    vendor: str | None
    response_time: float
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "response_time_ms": round(self.response_time * 1000, 2),
            "timestamp": self.timestamp.isoformat(),
        }


def arp_scan_single(ip: str, timeout: float = 2.0) -> ARPResult | None:
    """Perform ARP scan on a single IP address."""
    if not is_root():
        raise PermissionError("ARP scan", "Requires root privileges")

    conf.verb = 0  # Suppress Scapy output

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    start_time = datetime.now()

    try:
        answered, _ = srp(arp_request, timeout=timeout, verbose=False)
    except Exception as e:
        raise ScanError(f"ARP scan failed for {ip}", str(e)) from e

    if not answered:
        return None

    for sent, received in answered:
        response_time = None
        if hasattr(sent, "time") and hasattr(received, "time"):
            response_time = float(received.time - sent.time)
        if response_time is None:
            response_time = (datetime.now() - start_time).total_seconds()
        mac = format_mac(received.hwsrc)

        return ARPResult(
            ip=received.psrc,
            mac=mac,
            hostname=resolve_hostname(received.psrc),
            vendor=get_oui_vendor(mac),
            response_time=response_time,
            timestamp=datetime.fromtimestamp(float(received.time))
            if hasattr(received, "time")
            else start_time,
        )

    return None


def arp_scan(
    network: str,
    timeout: float | None = None,
    rate_limit: int | None = None,
) -> list[ARPResult]:
    """
    Perform ARP scan on a network range.

    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        timeout: Timeout per host in seconds
        rate_limit: Max packets per second (None for no limit)

    Returns:
        List of ARPResult for discovered hosts
    """
    if not is_root():
        raise PermissionError("ARP scan", "Requires root privileges")

    config = get_config()
    timeout = timeout or config.scan.timeout
    rate_limit = rate_limit or config.scan.rate_limit

    net = validate_network(network)
    conf.verb = 0

    # Build ARP requests for all hosts
    hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        return []

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=hosts)
    start_time = datetime.now()

    try:
        # Apply rate limiting if in non-fast mode
        inter = 1.0 / rate_limit if rate_limit and not config.fast_mode else 0
        answered, _ = srp(arp_request, timeout=timeout, inter=inter, verbose=False)
    except Exception as e:
        raise ScanError(f"ARP scan failed for {network}", str(e)) from e

    results = []
    for sent, received in answered:
        response_time = None
        if hasattr(sent, "time") and hasattr(received, "time"):
            response_time = float(received.time - sent.time)
        if response_time is None:
            response_time = (datetime.now() - start_time).total_seconds()
        mac = format_mac(received.hwsrc)

        result = ARPResult(
            ip=received.psrc,
            mac=mac,
            hostname=resolve_hostname(received.psrc),
            vendor=get_oui_vendor(mac),
            response_time=response_time,
            timestamp=datetime.fromtimestamp(float(received.time))
            if hasattr(received, "time")
            else start_time,
        )
        results.append(result)

    # Sort by IP address
    results.sort(key=lambda r: tuple(map(int, r.ip.split("."))))
    return results
