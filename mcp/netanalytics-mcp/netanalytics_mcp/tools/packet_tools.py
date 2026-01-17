"""Packet capture and analysis tools for MCP server - tcpdump, ngrep, tcpflow."""

from pathlib import Path
from typing import Annotated

from fastmcp import FastMCP

from netanalytics.core.config import get_config
from netanalytics.core.utils import get_interfaces, is_root
from netanalytics.wrappers.packet_tools_wrapper import (
    NgrepSearch,
    TcpdumpCapture,
    TcpflowExtractor,
)


def _validate_pcap_path(pcap_path: str) -> tuple[bool, str]:
    """Validate pcap path to prevent directory traversal."""
    path = Path(pcap_path).resolve()
    config = get_config()
    results_dir = config.results_dir.resolve()
    cwd = Path.cwd().resolve()

    if not (str(path).startswith(str(results_dir)) or str(path).startswith(str(cwd))):
        if not path.exists():
            return False, f"File not found: {pcap_path}"
        if not path.is_file():
            return False, f"Not a file: {pcap_path}"

    if path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        return False, f"File must be a pcap file: {pcap_path}"

    return True, str(path)


def register_packet_tools(mcp: FastMCP) -> None:
    """Register packet capture and analysis tools with the MCP server."""

    @mcp.tool()
    def tcpdump_capture(
        interface: Annotated[str, "Network interface to capture on (e.g., 'en0', 'eth0')"],
        count: Annotated[int, "Maximum number of packets to capture (default: 100)"] = 100,
        timeout: Annotated[int, "Capture timeout in seconds (default: 60)"] = 60,
        bpf_filter: Annotated[str | None, "BPF filter expression (e.g., 'tcp port 80')"] = None,
        output_file: Annotated[str | None, "Output pcap file path (optional)"] = None,
    ) -> dict:
        """Capture network traffic using tcpdump.

        tcpdump is a lightweight packet capture tool. Faster than tshark
        for simple captures. Requires root privileges.

        Common BPF filters:
        - 'tcp port 80' - HTTP traffic
        - 'udp port 53' - DNS traffic
        - 'host 192.168.1.1' - Traffic to/from specific host
        - 'net 192.168.1.0/24' - Traffic on subnet
        """
        if not is_root():
            return {
                "error": "tcpdump requires root privileges. Run with sudo.",
                "requires_root": True,
                "packets": [],
            }

        interfaces = get_interfaces()
        if interface not in interfaces:
            available = ", ".join(interfaces.keys())
            return {
                "error": f"Interface '{interface}' not found. Available: {available}",
                "packets": [],
            }

        try:
            capture = TcpdumpCapture()
            result = capture.capture(
                interface=interface,
                count=count,
                timeout=timeout,
                bpf_filter=bpf_filter,
                output_file=output_file,
            )

            return {
                "interface": result.interface,
                "packet_count": result.packet_count,
                "output_file": result.output_file,
                "filter": result.bpf_filter,
                "duration_seconds": (result.end_time - result.start_time).total_seconds(),
                "packets": [p.to_dict() for p in result.packets[:50]],
            }

        except Exception as e:
            return {"error": str(e), "packets": []}

    @mcp.tool()
    def tcpdump_read_pcap(
        pcap_path: Annotated[str, "Path to the pcap file to read"],
        bpf_filter: Annotated[str | None, "BPF filter expression (optional)"] = None,
        count: Annotated[int | None, "Maximum packets to read (optional)"] = None,
    ) -> dict:
        """Read and parse packets from a pcap file using tcpdump.

        Faster than tshark for simple packet listing. Good for
        quick inspection of pcap files.

        Returns parsed packet information including source, destination,
        protocol, and summary info.
        """
        valid, result = _validate_pcap_path(pcap_path)
        if not valid:
            return {"error": result, "packets": []}

        try:
            capture = TcpdumpCapture()
            result_data = capture.read_pcap(
                pcap_file=result,
                bpf_filter=bpf_filter,
                count=count,
            )

            return {
                "file": pcap_path,
                "packet_count": result_data.packet_count,
                "filter": result_data.bpf_filter,
                "packets": [p.to_dict() for p in result_data.packets[:100]],
            }

        except Exception as e:
            return {"error": str(e), "packets": []}

    @mcp.tool()
    def ngrep_search_pcap(
        pattern: Annotated[str, "Regex pattern to search for in packet payloads"],
        pcap_path: Annotated[str, "Path to the pcap file to search"],
        case_insensitive: Annotated[bool, "Case insensitive matching (default: False)"] = False,
    ) -> dict:
        """Search for patterns in packet payloads using ngrep.

        ngrep is like grep for network traffic. Search for strings
        or regex patterns in packet data.

        Examples:
        - 'password' - Find password strings
        - 'GET|POST' - Find HTTP methods
        - 'SELECT.*FROM' - Find SQL queries
        """
        valid, result = _validate_pcap_path(pcap_path)
        if not valid:
            return {"error": result, "matches": []}

        try:
            ngrep = NgrepSearch()
            result_data = ngrep.search_pcap(
                pattern=pattern,
                pcap_file=result,
                case_insensitive=case_insensitive,
            )

            return {
                "pattern": result_data.pattern,
                "file": pcap_path,
                "match_count": result_data.match_count,
                "matches": [m.to_dict() for m in result_data.matches[:50]],
            }

        except Exception as e:
            return {"error": str(e), "matches": []}

    @mcp.tool()
    def ngrep_search_live(
        pattern: Annotated[str, "Regex pattern to search for"],
        interface: Annotated[str, "Network interface to capture on"],
        timeout: Annotated[int, "Search timeout in seconds (default: 30)"] = 30,
        bpf_filter: Annotated[str | None, "BPF filter to narrow search (optional)"] = None,
        case_insensitive: Annotated[bool, "Case insensitive matching (default: False)"] = False,
    ) -> dict:
        """Search live traffic for patterns using ngrep.

        Captures and searches network traffic in real-time. Requires root.

        Useful for finding specific data in active connections:
        - API keys or tokens
        - Specific HTTP requests
        - Protocol commands
        """
        if not is_root():
            return {
                "error": "ngrep live capture requires root privileges. Run with sudo.",
                "requires_root": True,
                "matches": [],
            }

        interfaces = get_interfaces()
        if interface not in interfaces:
            available = ", ".join(interfaces.keys())
            return {
                "error": f"Interface '{interface}' not found. Available: {available}",
                "matches": [],
            }

        try:
            ngrep = NgrepSearch()
            result = ngrep.search_live(
                pattern=pattern,
                interface=interface,
                timeout=timeout,
                bpf_filter=bpf_filter,
                case_insensitive=case_insensitive,
            )

            return {
                "pattern": result.pattern,
                "interface": result.interface,
                "match_count": result.match_count,
                "matches": [m.to_dict() for m in result.matches[:50]],
            }

        except Exception as e:
            return {"error": str(e), "matches": []}

    @mcp.tool()
    def tcpflow_extract_streams(
        pcap_path: Annotated[str, "Path to the pcap file to analyze"],
        output_dir: Annotated[str | None, "Output directory for stream files (optional)"] = None,
        max_files: Annotated[int, "Maximum stream files to process (default: 50)"] = 50,
    ) -> dict:
        """Extract and reconstruct TCP streams from a pcap file.

        tcpflow separates TCP connections into individual files,
        making it easy to extract transferred content like:
        - HTTP requests/responses
        - File transfers
        - Application data

        Returns list of extracted streams with size and preview.
        """
        valid, result = _validate_pcap_path(pcap_path)
        if not valid:
            return {"error": result, "streams": []}

        try:
            extractor = TcpflowExtractor()
            result_data = extractor.extract_from_pcap(
                pcap_file=result,
                output_dir=output_dir,
                max_files=max_files,
            )

            return {
                "file": pcap_path,
                "output_dir": result_data.output_dir,
                "stream_count": result_data.stream_count,
                "total_bytes": result_data.total_bytes,
                "streams": [s.to_dict() for s in result_data.streams],
            }

        except Exception as e:
            return {"error": str(e), "streams": []}
