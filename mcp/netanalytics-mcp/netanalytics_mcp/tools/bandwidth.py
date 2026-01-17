"""Bandwidth monitoring tools for MCP server - bandwhich, vnstat."""

from typing import Annotated

from fastmcp import FastMCP

from netanalytics.core.utils import get_interfaces, is_root
from netanalytics.wrappers.bandwidth_wrapper import BandwhichMonitor, VnstatMonitor


def register_bandwidth_tools(mcp: FastMCP) -> None:
    """Register bandwidth monitoring tools with the MCP server."""

    @mcp.tool()
    def monitor_bandwidth(
        duration: Annotated[int, "Monitoring duration in seconds (default: 5)"] = 5,
        interface: Annotated[str | None, "Specific interface to monitor (optional)"] = None,
    ) -> dict:
        """Monitor current bandwidth usage per process and connection.

        Uses bandwhich to show real-time bandwidth utilization.
        Requires root privileges.

        Returns:
        - Per-process upload/download rates
        - Active connections with bandwidth
        - Total throughput statistics
        """
        if not is_root():
            return {
                "error": "Bandwidth monitoring requires root privileges. Run with sudo.",
                "requires_root": True,
                "processes": [],
            }

        if interface:
            interfaces = get_interfaces()
            if interface not in interfaces:
                available = ", ".join(interfaces.keys())
                return {
                    "error": f"Interface '{interface}' not found. Available: {available}",
                    "processes": [],
                }

        try:
            monitor = BandwhichMonitor()
            result = monitor.snapshot(duration=duration, interface=interface)

            # Format for readability
            processes = []
            for p in result.processes:
                data = p.to_dict()
                processes.append(data)

            return {
                "duration_seconds": result.duration_seconds,
                "total_upload_bytes_sec": result.total_upload_bytes_sec,
                "total_download_bytes_sec": result.total_download_bytes_sec,
                "process_count": len(result.processes),
                "connection_count": len(result.connections),
                "processes": processes[:20],  # Top 20 processes
                "connections": [c.to_dict() for c in result.connections[:30]],
            }

        except Exception as e:
            return {"error": str(e), "processes": []}

    @mcp.tool()
    def get_traffic_stats(
        interface: Annotated[str | None, "Specific interface (optional, default: all)"] = None,
        period: Annotated[
            str, "Period: 'hourly', 'daily', 'monthly', 'total' (default: daily)"
        ] = "daily",
    ) -> dict:
        """Get historical traffic statistics from vnstat.

        vnstat tracks traffic over time without active monitoring.
        Shows cumulative bytes sent/received.

        Note: vnstat daemon must be running for data collection.
        First run may show no data until enough traffic is logged.
        """
        try:
            vnstat = VnstatMonitor()
            result = vnstat.get_stats(interface=interface, period=period)

            if not result.interfaces:
                daemon_running = vnstat.is_daemon_running()
                return {
                    "warning": "No traffic data available yet",
                    "daemon_running": daemon_running,
                    "suggestion": "vnstat needs time to collect data. Check daemon status.",
                    "interfaces": [],
                }

            return {
                "period": result.period,
                "query_time": result.query_time.isoformat(),
                "interfaces": [i.to_dict() for i in result.interfaces],
            }

        except Exception as e:
            return {"error": str(e), "interfaces": []}

    @mcp.tool()
    def check_vnstat_status() -> dict:
        """Check vnstat daemon status and available interfaces.

        Returns daemon status and list of interfaces being tracked.
        Useful for diagnosing vnstat data availability issues.
        """
        try:
            vnstat = VnstatMonitor()

            daemon_running = vnstat.is_daemon_running()
            interfaces = vnstat.list_interfaces()

            return {
                "daemon_running": daemon_running,
                "tracked_interfaces": interfaces,
                "suggestion": (
                    "Start daemon with 'sudo vnstatd -d'" if not daemon_running
                    else "Daemon is running, data will accumulate over time"
                ),
            }

        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    def compare_interface_traffic(
        period: Annotated[str, "Period: 'daily', 'monthly', 'total' (default: daily)"] = "daily",
    ) -> dict:
        """Compare traffic across all network interfaces.

        Shows side-by-side comparison of bytes transferred on each
        interface. Useful for identifying primary traffic paths.
        """
        try:
            vnstat = VnstatMonitor()
            result = vnstat.get_stats(period=period)

            if not result.interfaces:
                return {
                    "warning": "No traffic data available",
                    "interfaces": [],
                }

            # Sort by total traffic
            sorted_ifaces = sorted(
                result.interfaces,
                key=lambda i: i.rx_bytes + i.tx_bytes,
                reverse=True,
            )

            comparison = []
            for iface in sorted_ifaces:
                total = iface.rx_bytes + iface.tx_bytes
                comparison.append({
                    "interface": iface.interface,
                    "rx_bytes": iface.rx_bytes,
                    "tx_bytes": iface.tx_bytes,
                    "total_bytes": total,
                    "rx_human": iface.to_dict()["rx_human"],
                    "tx_human": iface.to_dict()["tx_human"],
                })

            return {
                "period": period,
                "interface_count": len(comparison),
                "comparison": comparison,
            }

        except Exception as e:
            return {"error": str(e), "interfaces": []}
