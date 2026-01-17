"""Path analysis tools for MCP server - mtr network path tracing."""

from typing import Annotated

from fastmcp import FastMCP

from netanalytics.core.utils import is_root
from netanalytics.wrappers.path_wrapper import MtrAnalyzer


def register_path_tools(mcp: FastMCP) -> None:
    """Register path analysis tools with the MCP server."""

    @mcp.tool()
    def trace_network_path(
        target: Annotated[str, "Target hostname or IP address to trace"],
        count: Annotated[int, "Number of probes per hop (default: 10)"] = 10,
        resolve_dns: Annotated[bool, "Resolve hostnames (default: True)"] = True,
        ipv4_only: Annotated[bool, "Force IPv4 only (default: False)"] = False,
    ) -> dict:
        """Trace the network path to a target using mtr.

        mtr combines traceroute and ping to show hop-by-hop latency and packet loss.
        Requires root privileges for raw socket access.

        Returns path with per-hop statistics including:
        - Latency (best/avg/worst/stdev)
        - Packet loss percentage
        - Host/IP resolution
        """
        if not is_root():
            return {
                "error": "Path tracing requires root privileges. Run with sudo.",
                "requires_root": True,
                "hops": [],
            }

        try:
            analyzer = MtrAnalyzer()
            result = analyzer.trace(
                target=target,
                count=count,
                resolve_dns=resolve_dns,
                ipv4_only=ipv4_only,
            )

            return {
                "target": result.target,
                "hop_count": len(result.hops),
                "duration_seconds": (result.end_time - result.start_time).total_seconds(),
                "hops": [hop.to_dict() for hop in result.hops],
            }

        except Exception as e:
            return {"error": str(e), "hops": []}

    @mcp.tool()
    def quick_path_trace(
        target: Annotated[str, "Target hostname or IP address"],
    ) -> dict:
        """Quick network path trace with fewer probes.

        Uses 3 probes per hop for faster results. Good for initial
        path discovery. Requires root privileges.

        Returns hop-by-hop path with latency statistics.
        """
        if not is_root():
            return {
                "error": "Path tracing requires root privileges. Run with sudo.",
                "requires_root": True,
                "hops": [],
            }

        try:
            analyzer = MtrAnalyzer()
            result = analyzer.quick_trace(target)

            # Summarize key metrics
            total_hops = len(result.hops)
            responding_hops = len([h for h in result.hops if h.host or h.ip])
            avg_latency = None
            max_loss = 0.0

            for hop in result.hops:
                if hop.avg_ms is not None:
                    if avg_latency is None:
                        avg_latency = hop.avg_ms
                    else:
                        avg_latency = max(avg_latency, hop.avg_ms)
                max_loss = max(max_loss, hop.loss_percent)

            return {
                "target": result.target,
                "hop_count": total_hops,
                "responding_hops": responding_hops,
                "final_latency_ms": avg_latency,
                "max_packet_loss_percent": max_loss,
                "hops": [hop.to_dict() for hop in result.hops],
            }

        except Exception as e:
            return {"error": str(e), "hops": []}

    @mcp.tool()
    def analyze_path_quality(
        target: Annotated[str, "Target hostname or IP address"],
        count: Annotated[int, "Number of probes per hop (default: 20)"] = 20,
    ) -> dict:
        """Detailed path quality analysis with more probes.

        Uses specified probes per hop for accurate statistics. Identifies:
        - High latency hops (>100ms)
        - Packet loss issues (>5%)
        - Path asymmetry indicators

        Requires root privileges.
        """
        if not is_root():
            return {
                "error": "Path analysis requires root privileges. Run with sudo.",
                "requires_root": True,
                "analysis": {},
            }

        try:
            analyzer = MtrAnalyzer()
            result = analyzer.trace(target, count=count)

            # Analyze path quality
            high_latency_hops = []
            packet_loss_hops = []
            total_latency = 0.0
            latency_count = 0

            for hop in result.hops:
                if hop.avg_ms is not None:
                    total_latency += hop.avg_ms
                    latency_count += 1
                    if hop.avg_ms > 100:
                        high_latency_hops.append({
                            "hop": hop.hop_number,
                            "host": hop.host or hop.ip or "unknown",
                            "avg_ms": hop.avg_ms,
                        })

                if hop.loss_percent > 5:
                    packet_loss_hops.append({
                        "hop": hop.hop_number,
                        "host": hop.host or hop.ip or "unknown",
                        "loss_percent": hop.loss_percent,
                    })

            avg_latency = total_latency / latency_count if latency_count > 0 else None

            # Determine overall quality
            quality = "good"
            if len(packet_loss_hops) > 0 or len(high_latency_hops) > 2:
                quality = "poor"
            elif len(high_latency_hops) > 0:
                quality = "fair"

            return {
                "target": result.target,
                "hop_count": len(result.hops),
                "quality": quality,
                "average_latency_ms": avg_latency,
                "high_latency_hops": high_latency_hops,
                "packet_loss_hops": packet_loss_hops,
                "hops": [hop.to_dict() for hop in result.hops],
            }

        except Exception as e:
            return {"error": str(e), "analysis": {}}
