"""Discovery tools for MCP server - host discovery, port scanning, service detection."""

from typing import Annotated

from fastmcp import FastMCP

from netanalytics.core.utils import is_root, validate_network, validate_port_range
from netanalytics.discovery import arp_scan, detect_services, port_scan


def register_discovery_tools(mcp: FastMCP) -> None:
    """Register discovery tools with the MCP server."""

    @mcp.tool()
    def discover_hosts(
        network: Annotated[str, "Network CIDR to scan (e.g., '192.168.1.0/24')"],
        method: Annotated[str, "Discovery method: 'arp' or 'icmp' (default: arp)"] = "arp",
        timeout: Annotated[float, "Timeout per host in seconds (default: 2.0)"] = 2.0,
    ) -> dict:
        """Discover live hosts on a network using ARP or ICMP scanning.

        ARP scanning is more reliable for local networks but requires root privileges.
        ICMP scanning works across subnets but may be blocked by firewalls.

        Returns a dict with 'hosts' list containing IP, MAC (ARP only), hostname, and vendor info.
        """
        # Validate network format
        try:
            validate_network(network)
        except Exception as e:
            return {"error": str(e), "hosts": []}

        # Check root for methods that require it
        if method in ("arp", "icmp") and not is_root():
            return {
                "error": (
                    f"{method.upper()} scan requires root privileges. "
                    "Run the MCP server with sudo."
                ),
                "requires_root": True,
                "hosts": [],
            }

        try:
            if method == "arp":
                results = arp_scan(network, timeout=timeout)
                hosts = [
                    {
                        "ip": r.ip,
                        "mac": r.mac,
                        "hostname": r.hostname,
                        "vendor": r.vendor,
                    }
                    for r in results
                ]
            elif method == "icmp":
                from netanalytics.discovery.icmp_scan import icmp_scan_alive_only

                results = icmp_scan_alive_only(network, timeout=timeout)
                hosts = [
                    {
                        "ip": r.ip,
                        "hostname": r.hostname,
                    }
                    for r in results
                ]
            else:
                return {"error": f"Unknown method: {method}. Use 'arp' or 'icmp'.", "hosts": []}

            return {
                "network": network,
                "method": method,
                "host_count": len(hosts),
                "hosts": hosts,
            }

        except Exception as e:
            return {"error": str(e), "hosts": []}

    @mcp.tool()
    def scan_ports(
        target: Annotated[str, "Target IP address or hostname to scan"],
        ports: Annotated[
            str, "Ports to scan: range '1-1000' or list '22,80,443' (default: 1-1000)"
        ] = "1-1000",
        scan_type: Annotated[
            str, "Scan type: 'syn' (requires root) or 'connect' (default: connect)"
        ] = "connect",
        timeout: Annotated[float, "Timeout per port in seconds (default: 2.0)"] = 2.0,
        grab_banner: Annotated[
            bool, "Attempt to grab service banners (connect scan only)"
        ] = False,
    ) -> dict:
        """Scan ports on a target host.

        SYN scan is faster and stealthier but requires root privileges.
        Connect scan works without root but establishes full TCP connections.

        Returns port states: open, closed, or filtered.
        """
        # Validate port range
        try:
            validate_port_range(ports)
        except Exception as e:
            return {"error": str(e), "ports": []}

        # Check root for SYN scan
        if scan_type == "syn" and not is_root():
            return {
                "error": (
                    "SYN scan requires root privileges. "
                    "Use scan_type='connect' or run with sudo."
                ),
                "requires_root": True,
                "ports": [],
            }

        try:
            result = port_scan(
                target,
                ports=ports,
                scan_type=scan_type,
                timeout=timeout,
                grab_banner=grab_banner,
            )

            open_ports = result.get_open_ports()

            return {
                "target": target,
                "scan_type": scan_type,
                "open_count": result.open_count,
                "closed_count": result.closed_count,
                "filtered_count": result.filtered_count,
                "duration_seconds": (result.end_time - result.start_time).total_seconds(),
                "ports": [
                    {
                        "port": p.port,
                        "state": p.state.value,
                        "service": p.service,
                        "banner": p.banner,
                    }
                    for p in open_ports
                ],
            }

        except Exception as e:
            return {"error": str(e), "ports": []}

    @mcp.tool()
    def detect_service_versions(
        target: Annotated[str, "Target IP address or hostname"],
        ports: Annotated[str, "Ports to check: range '1-1000' or list '22,80,443'"],
    ) -> dict:
        """Detect services and versions running on open ports.

        Performs banner grabbing and service fingerprinting to identify
        what software is running on each port.

        Returns service name, version, and additional details for each port.
        """
        try:
            port_list = validate_port_range(ports)
        except Exception as e:
            return {"error": str(e), "services": []}

        try:
            results = detect_services(target, port_list)

            return {
                "target": target,
                "services": [
                    {
                        "port": s.port,
                        "service": s.service,
                        "version": s.version,
                        "banner": s.banner,
                        "protocol": s.protocol,
                    }
                    for s in results
                ],
            }

        except Exception as e:
            return {"error": str(e), "services": []}
