"""Wrapper for nmap using python-nmap library."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import nmap

from ..core.exceptions import ScanError, DependencyError
from ..core.utils import validate_ip, validate_network, check_dependency


@dataclass
class NmapHost:
    """Nmap scan result for a single host."""

    ip: str
    hostname: str | None
    state: str
    ports: list[dict]
    os_matches: list[dict]
    mac: str | None
    vendor: str | None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "ports": self.ports,
            "os_matches": self.os_matches,
            "mac": self.mac,
            "vendor": self.vendor,
        }


@dataclass
class NmapResult:
    """Complete nmap scan result."""

    command: str
    hosts: list[NmapHost]
    scan_info: dict
    start_time: datetime
    end_time: datetime

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "hosts": [h.to_dict() for h in self.hosts],
            "scan_info": self.scan_info,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
        }


class NmapScanner:
    """Wrapper for nmap network scanner."""

    def __init__(self) -> None:
        if not check_dependency("nmap"):
            raise DependencyError("nmap", "Install with: brew install nmap (macOS) or apt install nmap (Linux)")

        self.nm = nmap.PortScanner()

    def scan(
        self,
        target: str,
        ports: str | None = None,
        arguments: str = "",
        sudo: bool = False,
    ) -> NmapResult:
        """
        Run nmap scan on target.

        Args:
            target: IP address, hostname, or CIDR network
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            arguments: Additional nmap arguments
            sudo: Run with sudo (required for some scan types)

        Returns:
            NmapResult with scan data
        """
        start_time = datetime.now()

        try:
            self.nm.scan(hosts=target, ports=ports, arguments=arguments, sudo=sudo)
        except nmap.PortScannerError as e:
            raise ScanError(f"Nmap scan failed for {target}", str(e))

        hosts = []
        for host in self.nm.all_hosts():
            host_data = self.nm[host]

            # Extract port information
            ports_list = []
            for proto in host_data.all_protocols():
                for port, port_data in host_data[proto].items():
                    ports_list.append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": port_data.get("state"),
                            "service": port_data.get("name"),
                            "product": port_data.get("product"),
                            "version": port_data.get("version"),
                            "extrainfo": port_data.get("extrainfo"),
                        }
                    )

            # Extract OS information
            os_matches = []
            if "osmatch" in host_data:
                for os_match in host_data["osmatch"]:
                    os_matches.append(
                        {
                            "name": os_match.get("name"),
                            "accuracy": os_match.get("accuracy"),
                            "osclass": os_match.get("osclass", []),
                        }
                    )

            # Extract MAC and vendor
            mac = None
            vendor = None
            if "addresses" in host_data:
                mac = host_data["addresses"].get("mac")
            if "vendor" in host_data and mac:
                vendor = host_data["vendor"].get(mac)

            hosts.append(
                NmapHost(
                    ip=host,
                    hostname=host_data.hostname() if hasattr(host_data, "hostname") else None,
                    state=host_data.state() if hasattr(host_data, "state") else "unknown",
                    ports=ports_list,
                    os_matches=os_matches,
                    mac=mac,
                    vendor=vendor,
                )
            )

        end_time = datetime.now()

        return NmapResult(
            command=self.nm.command_line(),
            hosts=hosts,
            scan_info=self.nm.scaninfo(),
            start_time=start_time,
            end_time=end_time,
        )

    def quick_scan(self, target: str) -> NmapResult:
        """Fast scan of common ports."""
        return self.scan(target, arguments="-F -T4")

    def service_scan(self, target: str, ports: str | None = None) -> NmapResult:
        """Scan with service version detection."""
        return self.scan(target, ports=ports, arguments="-sV")

    def os_scan(self, target: str) -> NmapResult:
        """Scan with OS detection (requires root)."""
        return self.scan(target, arguments="-O", sudo=True)

    def comprehensive_scan(self, target: str) -> NmapResult:
        """Comprehensive scan with service and OS detection."""
        return self.scan(target, arguments="-sV -sC -O -T4", sudo=True)

    def vulnerability_scan(self, target: str) -> NmapResult:
        """Scan using nmap vulnerability scripts."""
        return self.scan(target, arguments="-sV --script=vuln", sudo=True)

    def stealth_scan(self, target: str, ports: str | None = None) -> NmapResult:
        """SYN stealth scan (requires root)."""
        return self.scan(target, ports=ports, arguments="-sS", sudo=True)

    def ping_scan(self, network: str) -> NmapResult:
        """Ping scan to discover live hosts."""
        return self.scan(network, arguments="-sn")
