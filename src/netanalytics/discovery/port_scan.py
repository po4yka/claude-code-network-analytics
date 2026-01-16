"""Port scanning using Scapy and sockets."""

import socket
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from scapy.all import IP, TCP, conf, sr1

from ..core.config import get_config
from ..core.exceptions import PermissionError, ScanError
from ..core.utils import is_root, resolve_target, validate_port_range


class PortState(Enum):
    """Port state enumeration."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class PortResult:
    """Result of a port scan for a single port."""

    port: int
    state: PortState
    service: str | None
    banner: str | None
    response_time: float | None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "banner": self.banner,
            "response_time_ms": round(self.response_time * 1000, 2)
            if self.response_time is not None
            else None,
        }


@dataclass
class ScanResult:
    """Result of a complete port scan."""

    target: str
    ports: list[PortResult]
    scan_type: str
    start_time: datetime
    end_time: datetime
    open_count: int
    closed_count: int
    filtered_count: int

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "summary": {
                "open": self.open_count,
                "closed": self.closed_count,
                "filtered": self.filtered_count,
                "total": len(self.ports),
            },
            "ports": [p.to_dict() for p in self.ports if p.state == PortState.OPEN],
        }

    def get_open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == PortState.OPEN]


# Common service name mapping
COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    119: "nntp",
    123: "ntp",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    194: "irc",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


def get_service_name(port: int) -> str | None:
    """Get common service name for a port."""
    return COMMON_SERVICES.get(port)


def syn_scan(
    target: str,
    ports: str = "1-1000",
    timeout: float | None = None,
    rate_limit: int | None = None,
) -> ScanResult:
    """
    Perform TCP SYN (half-open) scan.

    Requires root privileges. Sends SYN packets and analyzes responses.

    Args:
        target: Target IP address
        ports: Port range (e.g., "1-1000" or "22,80,443")
        timeout: Timeout per port in seconds
        rate_limit: Max packets per second

    Returns:
        ScanResult with port states
    """
    if not is_root():
        raise PermissionError("SYN scan", "Requires root privileges")

    config = get_config()
    timeout = timeout or config.scan.timeout
    rate_limit = rate_limit or config.scan.rate_limit

    target_ip = resolve_target(target)
    port_list = validate_port_range(ports)
    conf.verb = 0

    start_time = datetime.now()
    results = []

    inter = 1.0 / rate_limit if rate_limit and not config.fast_mode else 0

    for port in port_list:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        port_start = datetime.now()

        try:
            response = sr1(packet, timeout=timeout, verbose=False)
            response_time = (datetime.now() - port_start).total_seconds()
        except Exception:
            results.append(
                PortResult(
                    port=port,
                    state=PortState.FILTERED,
                    service=get_service_name(port),
                    banner=None,
                    response_time=None,
                )
            )
            continue

        if response is None:
            state = PortState.FILTERED
            response_time = None
        elif response.haslayer(TCP):
            tcp_flags = response.getlayer(TCP).flags
            if tcp_flags == 0x12:  # SYN-ACK
                state = PortState.OPEN
                # Send RST to close connection
                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
                sr1(rst_packet, timeout=0.5, verbose=False)
            elif tcp_flags == 0x14:  # RST-ACK
                state = PortState.CLOSED
            else:
                state = PortState.FILTERED
        else:
            state = PortState.FILTERED

        results.append(
            PortResult(
                port=port,
                state=state,
                service=get_service_name(port),
                banner=None,
                response_time=response_time if state == PortState.OPEN else None,
            )
        )

        # Rate limiting delay
        if inter > 0:
            import time

            time.sleep(inter)

    end_time = datetime.now()

    return ScanResult(
        target=target,
        ports=results,
        scan_type="syn",
        start_time=start_time,
        end_time=end_time,
        open_count=sum(1 for p in results if p.state == PortState.OPEN),
        closed_count=sum(1 for p in results if p.state == PortState.CLOSED),
        filtered_count=sum(1 for p in results if p.state == PortState.FILTERED),
    )


def connect_scan(
    target: str,
    ports: str = "1-1000",
    timeout: float | None = None,
    rate_limit: int | None = None,
    grab_banner: bool = False,
) -> ScanResult:
    """
    Perform TCP connect scan (full 3-way handshake).

    Does not require root privileges. Completes full TCP handshake.

    Args:
        target: Target IP address
        ports: Port range (e.g., "1-1000" or "22,80,443")
        timeout: Timeout per port in seconds
        rate_limit: Max packets per second
        grab_banner: Attempt to grab service banners

    Returns:
        ScanResult with port states
    """
    config = get_config()
    timeout = timeout or config.scan.timeout
    rate_limit = rate_limit or config.scan.rate_limit

    target_ip = resolve_target(target)
    port_list = validate_port_range(ports)

    start_time = datetime.now()
    results = []

    inter = 1.0 / rate_limit if rate_limit and not config.fast_mode else 0

    for port in port_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        port_start = datetime.now()

        try:
            result = sock.connect_ex((target_ip, port))
            response_time = (datetime.now() - port_start).total_seconds()

            if result == 0:
                state = PortState.OPEN
                banner = None

                if grab_banner:
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        if len(banner) > 200:
                            banner = banner[:200] + "..."
                    except Exception:
                        pass
            else:
                state = PortState.CLOSED
                banner = None
                response_time = None

        except TimeoutError:
            state = PortState.FILTERED
            banner = None
            response_time = None
        except OSError:
            state = PortState.FILTERED
            banner = None
            response_time = None
        finally:
            sock.close()

        results.append(
            PortResult(
                port=port,
                state=state,
                service=get_service_name(port),
                banner=banner,
                response_time=response_time,
            )
        )

        # Rate limiting delay
        if inter > 0:
            import time

            time.sleep(inter)

    end_time = datetime.now()

    return ScanResult(
        target=target,
        ports=results,
        scan_type="connect",
        start_time=start_time,
        end_time=end_time,
        open_count=sum(1 for p in results if p.state == PortState.OPEN),
        closed_count=sum(1 for p in results if p.state == PortState.CLOSED),
        filtered_count=sum(1 for p in results if p.state == PortState.FILTERED),
    )


def port_scan(
    target: str,
    ports: str = "1-1000",
    scan_type: str = "connect",
    timeout: float | None = None,
    rate_limit: int | None = None,
    grab_banner: bool = False,
) -> ScanResult:
    """
    Perform port scan with specified type.

    Args:
        target: Target IP address
        ports: Port range
        scan_type: "syn" or "connect"
        timeout: Timeout per port
        rate_limit: Max packets per second
        grab_banner: Grab banners (connect scan only)

    Returns:
        ScanResult with port states
    """
    if scan_type == "syn":
        return syn_scan(target, ports, timeout, rate_limit)
    elif scan_type == "connect":
        return connect_scan(target, ports, timeout, rate_limit, grab_banner)
    else:
        raise ScanError(f"Unknown scan type: {scan_type}", "Use 'syn' or 'connect'")
