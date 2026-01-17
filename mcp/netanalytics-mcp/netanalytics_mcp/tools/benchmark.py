"""Network throughput benchmarking tools for MCP server - iperf3."""

from typing import Annotated

from fastmcp import FastMCP

from netanalytics.wrappers.iperf_wrapper import IperfClient


def register_benchmark_tools(mcp: FastMCP) -> None:
    """Register network benchmarking tools with the MCP server."""

    @mcp.tool()
    def benchmark_throughput(
        server: Annotated[str, "iperf3 server hostname or IP address"],
        port: Annotated[int, "Server port (default: 5201)"] = 5201,
        duration: Annotated[int, "Test duration in seconds (default: 10)"] = 10,
        protocol: Annotated[str, "Protocol: 'tcp' or 'udp' (default: tcp)"] = "tcp",
        reverse: Annotated[bool, "Test download speed instead of upload (default: False)"] = False,
        parallel: Annotated[int, "Number of parallel streams (default: 1)"] = 1,
    ) -> dict:
        """Benchmark network throughput to an iperf3 server.

        Measures maximum achievable bandwidth between client and server.
        Requires an iperf3 server running on the target.

        Public iperf3 servers available at:
        - iperf.he.net
        - speedtest.wtnet.de
        - iperf.biznetnetworks.com

        Returns throughput in Mbps, retransmits, and latency statistics.
        """
        try:
            client = IperfClient()
            result = client.test(
                server=server,
                port=port,
                duration=duration,
                protocol=protocol,
                reverse=reverse,
                parallel=parallel,
            )

            if result.error:
                return {"error": result.error, "summary": {}}

            summary = result.summary.to_dict()

            return {
                "server": result.server,
                "port": result.port,
                "protocol": result.protocol,
                "direction": result.direction,
                "duration_seconds": result.duration_sec,
                "mbps_sent": summary["mbps_sent"],
                "mbps_received": summary["mbps_received"],
                "bytes_sent": summary["bytes_sent"],
                "bytes_received": summary["bytes_received"],
                "retransmits": summary["retransmits"],
                "mean_rtt_ms": summary["mean_rtt_ms"],
                "intervals": [i.to_dict() for i in result.intervals],
            }

        except Exception as e:
            return {"error": str(e), "summary": {}}

    @mcp.tool()
    def quick_speed_test(
        server: Annotated[str, "iperf3 server hostname or IP address"],
    ) -> dict:
        """Quick 5-second upload speed test.

        Fast throughput measurement for quick network assessment.
        Use for initial speed checks before detailed testing.
        """
        try:
            client = IperfClient()
            result = client.quick_test(server)

            if result.error:
                return {"error": result.error}

            summary = result.summary.to_dict()

            return {
                "server": result.server,
                "direction": "upload",
                "mbps": summary["mbps_sent"],
                "bytes_transferred": summary["bytes_sent"],
                "duration_seconds": 5,
            }

        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    def test_download_speed(
        server: Annotated[str, "iperf3 server hostname or IP address"],
        duration: Annotated[int, "Test duration in seconds (default: 10)"] = 10,
    ) -> dict:
        """Test download speed from an iperf3 server.

        Measures incoming bandwidth by running reverse test.
        Server sends data to client for measurement.
        """
        try:
            client = IperfClient()
            result = client.download_test(server, duration)

            if result.error:
                return {"error": result.error}

            summary = result.summary.to_dict()

            return {
                "server": result.server,
                "direction": "download",
                "mbps": summary["mbps_received"],
                "bytes_transferred": summary["bytes_received"],
                "duration_seconds": duration,
            }

        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    def test_bidirectional_throughput(
        server: Annotated[str, "iperf3 server hostname or IP address"],
        duration: Annotated[int, "Test duration in seconds (default: 10)"] = 10,
    ) -> dict:
        """Test both upload and download simultaneously.

        Measures throughput in both directions at the same time.
        Useful for assessing full-duplex capability.
        """
        try:
            client = IperfClient()
            result = client.bidirectional_test(server, duration)

            if result.error:
                return {"error": result.error}

            summary = result.summary.to_dict()

            return {
                "server": result.server,
                "direction": "bidirectional",
                "mbps_upload": summary["mbps_sent"],
                "mbps_download": summary["mbps_received"],
                "total_mbps": summary["mbps_sent"] + summary["mbps_received"],
                "duration_seconds": duration,
            }

        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    def test_udp_jitter(
        server: Annotated[str, "iperf3 server hostname or IP address"],
        bandwidth: Annotated[str, "Target bandwidth (e.g., '100M', '1G')"] = "100M",
        duration: Annotated[int, "Test duration in seconds (default: 10)"] = 10,
    ) -> dict:
        """Test UDP throughput and jitter.

        UDP testing shows packet loss and jitter, important for:
        - VoIP quality assessment
        - Video streaming capability
        - Real-time application performance

        Note: UDP tests require bandwidth specification to prevent flooding.
        """
        try:
            client = IperfClient()
            result = client.udp_test(server, bandwidth, duration)

            if result.error:
                return {"error": result.error}

            summary = result.summary.to_dict()

            return {
                "server": result.server,
                "protocol": "UDP",
                "target_bandwidth": bandwidth,
                "mbps_achieved": summary["mbps_sent"],
                "duration_seconds": duration,
                "intervals": [i.to_dict() for i in result.intervals],
            }

        except Exception as e:
            return {"error": str(e)}
