"""Traffic analysis tools for MCP server - packet capture and protocol analysis."""

from pathlib import Path
from typing import Annotated

from fastmcp import FastMCP

from netanalytics.core.config import get_config
from netanalytics.core.utils import get_interfaces, is_root
from netanalytics.traffic import analyze_pcap, capture_packets, extract_dns, extract_http


def _validate_pcap_path(pcap_path: str) -> tuple[bool, str]:
    """Validate pcap path to prevent directory traversal."""
    path = Path(pcap_path).resolve()
    config = get_config()
    results_dir = config.results_dir.resolve()

    # Allow absolute paths within results directory or current working directory
    cwd = Path.cwd().resolve()
    if not (str(path).startswith(str(results_dir)) or str(path).startswith(str(cwd))):
        # Check if it's a readable file at all (user might have explicit path)
        if not path.exists():
            return False, f"File not found: {pcap_path}"
        if not path.is_file():
            return False, f"Not a file: {pcap_path}"

    if path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        return False, f"File must be a pcap file: {pcap_path}"

    return True, str(path)


def register_traffic_tools(mcp: FastMCP) -> None:
    """Register traffic analysis tools with the MCP server."""

    @mcp.tool()
    def capture_traffic(
        interface: Annotated[str, "Network interface to capture on (e.g., 'en0', 'eth0')"],
        count: Annotated[int, "Maximum number of packets to capture (default: 100)"] = 100,
        timeout: Annotated[int, "Capture timeout in seconds (default: 60)"] = 60,
        bpf_filter: Annotated[str | None, "BPF filter expression (e.g., 'tcp port 80')"] = None,
        output_file: Annotated[str | None, "Output pcap file path (optional)"] = None,
    ) -> dict:
        """Capture network traffic on an interface.

        Requires root privileges. Use BPF filters to capture specific traffic types.
        Common filters: 'tcp port 80', 'udp port 53', 'host 192.168.1.1'.

        Returns packet count and summary statistics.
        """
        if not is_root():
            return {
                "error": "Packet capture requires root privileges. Run the MCP server with sudo.",
                "requires_root": True,
                "packets": [],
            }

        # Validate interface exists
        interfaces = get_interfaces()
        if interface not in interfaces:
            available = ", ".join(interfaces.keys())
            return {
                "error": f"Interface '{interface}' not found. Available: {available}",
                "packets": [],
            }

        try:
            packets = capture_packets(
                interface=interface,
                count=count,
                timeout=timeout,
                bpf_filter=bpf_filter,
                output_file=output_file,
            )

            # Summarize packets
            protocol_counts = {}
            for pkt in packets:
                proto = pkt.get("protocol", "unknown")
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            return {
                "interface": interface,
                "packet_count": len(packets),
                "output_file": output_file,
                "filter": bpf_filter,
                "protocol_summary": protocol_counts,
            }

        except Exception as e:
            return {"error": str(e), "packets": []}

    @mcp.tool()
    def analyze_pcap_file(
        pcap_path: Annotated[str, "Path to the pcap file to analyze"],
        protocol: Annotated[
            str, "Protocol filter: 'all', 'tcp', 'udp', 'http', 'dns' (default: all)"
        ] = "all",
    ) -> dict:
        """Analyze a pcap file and extract statistics.

        Provides packet counts by protocol, top talkers (IPs with most traffic),
        port distribution, and timing information.

        Returns detailed traffic statistics and protocol breakdown.
        """
        valid, result = _validate_pcap_path(pcap_path)
        if not valid:
            return {"error": result, "stats": {}}

        try:
            stats = analyze_pcap(result, protocol_filter=protocol)

            return {
                "file": pcap_path,
                "protocol_filter": protocol,
                "stats": stats.to_dict(),
            }

        except Exception as e:
            return {"error": str(e), "stats": {}}

    @mcp.tool()
    def extract_dns_queries(
        pcap_path: Annotated[str, "Path to the pcap file"],
    ) -> dict:
        """Extract DNS queries and responses from a pcap file.

        Parses DNS packets to extract queried domains, response codes,
        resolved IPs, and query types (A, AAAA, MX, etc.).

        Useful for analyzing DNS traffic patterns and detecting anomalies.
        """
        valid, result = _validate_pcap_path(pcap_path)
        if not valid:
            return {"error": result, "queries": []}

        try:
            dns_data = extract_dns(result)

            return {
                "file": pcap_path,
                "query_count": len(dns_data),
                "queries": dns_data,
            }

        except Exception as e:
            return {"error": str(e), "queries": []}

    @mcp.tool()
    def extract_http_requests(
        pcap_path: Annotated[str, "Path to the pcap file"],
    ) -> dict:
        """Extract HTTP requests and responses from a pcap file.

        Parses HTTP traffic to extract methods, URLs, headers, status codes,
        and response sizes. Works with unencrypted HTTP traffic only.

        Returns list of HTTP transactions with request/response details.
        """
        valid, result = _validate_pcap_path(pcap_path)
        if not valid:
            return {"error": result, "requests": []}

        try:
            http_data = extract_http(result)

            return {
                "file": pcap_path,
                "request_count": len(http_data),
                "requests": http_data,
            }

        except Exception as e:
            return {"error": str(e), "requests": []}
