"""Service detection and banner grabbing."""

import re
import socket
from dataclasses import dataclass

from ..core.utils import resolve_target, validate_port_range


@dataclass
class ServiceInfo:
    """Detected service information."""

    port: int
    protocol: str
    service: str | None
    version: str | None
    banner: str | None
    extra_info: dict | None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "extra_info": self.extra_info,
        }


# Service probes for different protocols
SERVICE_PROBES = {
    "http": {
        "probe": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "pattern": rb"HTTP/[\d.]+\s+\d+",
    },
    "ssh": {
        "probe": b"",  # SSH sends banner first
        "pattern": rb"SSH-[\d.]+-\S+",
    },
    "ftp": {
        "probe": b"",  # FTP sends banner first
        "pattern": rb"220[- ]",
    },
    "smtp": {
        "probe": b"",
        "pattern": rb"220[- ].*SMTP",
    },
    "pop3": {
        "probe": b"",
        "pattern": rb"\+OK",
    },
    "imap": {
        "probe": b"",
        "pattern": rb"\* OK",
    },
    "mysql": {
        "probe": b"",
        "pattern": rb"^.\x00\x00\x00\x0a[\d.]+",
    },
    "redis": {
        "probe": b"PING\r\n",
        "pattern": rb"\+PONG",
    },
}


def _grab_banner(ip: str, port: int, timeout: float = 5.0) -> str | None:
    """Grab raw banner from a service."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))

        # Try to receive initial banner
        try:
            sock.setblocking(False)
            import select

            ready = select.select([sock], [], [], 2.0)
            if ready[0]:
                banner = sock.recv(1024)
                if banner:
                    return banner.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        # If no banner, try HTTP probe
        sock.setblocking(True)
        sock.settimeout(timeout)
        sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        response = sock.recv(1024)
        return response.decode("utf-8", errors="ignore").strip()

    except Exception:
        return None
    finally:
        sock.close()


def _parse_ssh_banner(banner: str) -> dict:
    """Parse SSH banner to extract version info."""
    info = {"service": "ssh"}

    match = re.match(r"SSH-([\d.]+)-(\S+)", banner)
    if match:
        info["protocol_version"] = match.group(1)
        info["software"] = match.group(2)

        # Try to extract version
        version_match = re.search(r"OpenSSH[_-]?([\d.p]+)", banner, re.I)
        if version_match:
            info["version"] = version_match.group(1)
            info["product"] = "OpenSSH"

    return info


def _parse_http_banner(banner: str) -> dict[str, str | int]:
    """Parse HTTP response to extract server info."""
    info: dict[str, str | int] = {"service": "http"}

    # Extract status code
    status_match = re.match(r"HTTP/[\d.]+\s+(\d+)", banner)
    if status_match:
        info["status_code"] = int(status_match.group(1))

    # Extract server header
    server_match = re.search(r"Server:\s*(.+?)(?:\r?\n|$)", banner, re.I)
    if server_match:
        server = server_match.group(1).strip()
        info["server"] = server

        # Try to parse server/version
        if "nginx" in server.lower():
            info["product"] = "nginx"
            version_match = re.search(r"nginx/([\d.]+)", server, re.I)
            if version_match:
                info["version"] = version_match.group(1)
        elif "apache" in server.lower():
            info["product"] = "Apache"
            version_match = re.search(r"Apache/([\d.]+)", server, re.I)
            if version_match:
                info["version"] = version_match.group(1)

    return info


def _parse_ftp_banner(banner: str) -> dict:
    """Parse FTP banner."""
    info = {"service": "ftp"}

    # Common FTP servers
    if "vsftpd" in banner.lower():
        info["product"] = "vsftpd"
        version_match = re.search(r"vsftpd\s+([\d.]+)", banner, re.I)
        if version_match:
            info["version"] = version_match.group(1)
    elif "proftpd" in banner.lower():
        info["product"] = "ProFTPD"
        version_match = re.search(r"ProFTPD\s+([\d.]+)", banner, re.I)
        if version_match:
            info["version"] = version_match.group(1)

    return info


def detect_service(ip: str, port: int, timeout: float = 5.0) -> ServiceInfo:
    """
    Detect service running on a specific port.

    Args:
        ip: Target IP address
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceInfo with detected service details
    """
    resolved_ip = resolve_target(ip)

    banner = _grab_banner(resolved_ip, port, timeout)

    if not banner:
        return ServiceInfo(
            port=port,
            protocol="tcp",
            service=None,
            version=None,
            banner=None,
            extra_info=None,
        )

    # Try to identify service from banner
    service = None
    version = None
    extra_info = {}

    if banner.startswith("SSH-"):
        info = _parse_ssh_banner(banner)
        service = str(info.get("service", "ssh"))
        version = str(info["version"]) if info.get("version") else None
        extra_info = info

    elif banner.startswith("HTTP/") or "HTTP/" in banner:
        info = _parse_http_banner(banner)
        service = str(info.get("service", "http"))
        version = str(info["version"]) if info.get("version") else None
        extra_info = info

    elif banner.startswith("220"):
        if "smtp" in banner.lower() or "mail" in banner.lower():
            service = "smtp"
        else:
            info = _parse_ftp_banner(banner)
            service = str(info.get("service", "ftp"))
            version = str(info["version"]) if info.get("version") else None
            extra_info = info

    elif banner.startswith("+OK"):
        service = "pop3"

    elif banner.startswith("* OK"):
        service = "imap"

    elif "+PONG" in banner:
        service = "redis"

    # Truncate long banners
    if banner and len(banner) > 500:
        banner = banner[:500] + "..."

    return ServiceInfo(
        port=port,
        protocol="tcp",
        service=service,
        version=version,
        banner=banner,
        extra_info=extra_info if extra_info else None,
    )


def detect_services(
    ip: str,
    ports: str | list[int],
    timeout: float = 5.0,
) -> list[ServiceInfo]:
    """
    Detect services on multiple ports.

    Args:
        ip: Target IP address
        ports: Port range string or list of ports
        timeout: Connection timeout per port

    Returns:
        List of ServiceInfo for each port
    """
    resolved_ip = resolve_target(ip)

    port_list = validate_port_range(ports) if isinstance(ports, str) else ports

    results = []
    for port in port_list:
        result = detect_service(resolved_ip, port, timeout)
        results.append(result)

    return results
