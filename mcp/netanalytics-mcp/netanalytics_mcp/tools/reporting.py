"""Reporting tools for MCP server - report generation and interface listing."""

from typing import Annotated

from fastmcp import FastMCP

from netanalytics.core.config import get_config
from netanalytics.core.utils import get_default_interface, get_interfaces
from netanalytics.output import generate_report


def register_reporting_tools(mcp: FastMCP) -> None:
    """Register reporting tools with the MCP server."""

    @mcp.tool()
    def create_network_report(
        target: Annotated[str, "Target IP, hostname, or network CIDR"],
        format: Annotated[
            str, "Report format: 'html', 'md', or 'json' (default: html)"
        ] = "html",
        output_path: Annotated[
            str | None, "Output file path (auto-generated if not provided)"
        ] = None,
    ) -> dict:
        """Generate a comprehensive network report for a target.

        The report includes:
        - Host discovery results
        - Open ports and services
        - Security assessment findings
        - Network topology (if applicable)
        - Recommendations

        Returns the path to the generated report file.
        """
        if format not in ("html", "md", "json"):
            return {
                "error": f"Invalid format: {format}. Use 'html', 'md', or 'json'.",
                "path": None,
            }

        try:
            report_path = generate_report(
                target,
                output_format=format,
                output_file=output_path,
            )

            return {
                "target": target,
                "format": format,
                "path": str(report_path),
            }

        except Exception as e:
            return {"error": str(e), "path": None}

    @mcp.tool()
    def list_network_interfaces() -> dict:
        """List available network interfaces on the system.

        Returns interface names with their IPv4/IPv6 addresses, MAC addresses,
        status (up/down), speed, and MTU.

        Useful for identifying which interface to use for packet capture.
        """
        try:
            interfaces = get_interfaces()
            default = get_default_interface()

            interface_list = []
            for name, info in interfaces.items():
                interface_list.append({
                    "name": name,
                    "ipv4": info.get("ipv4"),
                    "ipv6": info.get("ipv6"),
                    "mac": info.get("mac"),
                    "is_up": info.get("is_up", False),
                    "speed_mbps": info.get("speed"),
                    "mtu": info.get("mtu"),
                    "is_default": name == default,
                })

            return {
                "interface_count": len(interface_list),
                "default_interface": default,
                "interfaces": interface_list,
            }

        except Exception as e:
            return {"error": str(e), "interfaces": []}

    @mcp.tool()
    def get_results_directory() -> dict:
        """Get the path to the results directory.

        Returns the configured results directory path and lists any existing
        result files (pcaps, reports, scan outputs).
        """
        try:
            config = get_config()
            results_dir = config.results_dir

            files = []
            if results_dir.exists():
                for f in results_dir.iterdir():
                    if f.is_file():
                        files.append({
                            "name": f.name,
                            "path": str(f),
                            "size_bytes": f.stat().st_size,
                            "modified": f.stat().st_mtime,
                        })

            return {
                "results_dir": str(results_dir),
                "exists": results_dir.exists(),
                "file_count": len(files),
                "files": sorted(files, key=lambda x: x["modified"], reverse=True),
            }

        except Exception as e:
            return {"error": str(e), "results_dir": None}
