"""Wrapper for iperf3 network throughput testing."""

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime

from ..core.exceptions import DependencyError, ScanError
from ..core.utils import check_dependency


@dataclass
class IperfInterval:
    """Single interval result from iperf3 test."""

    start_sec: float
    end_sec: float
    bytes_transferred: int
    bits_per_second: float
    retransmits: int | None
    congestion_window: int | None

    def to_dict(self) -> dict:
        return {
            "start_sec": self.start_sec,
            "end_sec": self.end_sec,
            "bytes_transferred": self.bytes_transferred,
            "bits_per_second": self.bits_per_second,
            "mbps": self.bits_per_second / 1_000_000,
            "retransmits": self.retransmits,
            "congestion_window": self.congestion_window,
        }


@dataclass
class IperfSummary:
    """Summary statistics from iperf3 test."""

    bytes_sent: int
    bytes_received: int
    bits_per_second_sent: float
    bits_per_second_received: float
    retransmits: int | None
    max_congestion_window: int | None
    min_rtt_ms: float | None
    mean_rtt_ms: float | None
    max_rtt_ms: float | None

    def to_dict(self) -> dict:
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "bits_per_second_sent": self.bits_per_second_sent,
            "bits_per_second_received": self.bits_per_second_received,
            "mbps_sent": self.bits_per_second_sent / 1_000_000,
            "mbps_received": self.bits_per_second_received / 1_000_000,
            "retransmits": self.retransmits,
            "max_congestion_window": self.max_congestion_window,
            "min_rtt_ms": self.min_rtt_ms,
            "mean_rtt_ms": self.mean_rtt_ms,
            "max_rtt_ms": self.max_rtt_ms,
        }


@dataclass
class IperfResult:
    """Complete iperf3 test result."""

    server: str
    port: int
    protocol: str
    duration_sec: int
    direction: str  # "upload", "download", "bidirectional"
    intervals: list[IperfInterval]
    summary: IperfSummary
    start_time: datetime
    end_time: datetime
    error: str | None

    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "port": self.port,
            "protocol": self.protocol,
            "duration_sec": self.duration_sec,
            "direction": self.direction,
            "intervals": [i.to_dict() for i in self.intervals],
            "summary": self.summary.to_dict(),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "error": self.error,
        }


class IperfClient:
    """Wrapper for iperf3 network throughput testing.

    iperf3 is a tool for active measurements of the maximum achievable
    bandwidth on IP networks. Supports TCP and UDP with various tuning options.
    """

    def __init__(self) -> None:
        if not check_dependency("iperf3"):
            raise DependencyError(
                "iperf3",
                "Install with: brew install iperf3 (macOS) or apt install iperf3 (Linux)",
            )

    def test(
        self,
        server: str,
        port: int = 5201,
        duration: int = 10,
        protocol: str = "tcp",
        reverse: bool = False,
        bidirectional: bool = False,
        parallel: int = 1,
        bandwidth: str | None = None,
        window_size: str | None = None,
    ) -> IperfResult:
        """
        Run iperf3 throughput test.

        Args:
            server: iperf3 server hostname or IP
            port: Server port (default: 5201)
            duration: Test duration in seconds
            protocol: "tcp" or "udp"
            reverse: Test download instead of upload
            bidirectional: Test both directions simultaneously
            parallel: Number of parallel streams
            bandwidth: Target bandwidth (e.g., "100M" for UDP)
            window_size: TCP window size (e.g., "256K")

        Returns:
            IperfResult with test data
        """
        start_time = datetime.now()

        cmd = [
            "iperf3",
            "-c", server,
            "-p", str(port),
            "-t", str(duration),
            "-J",  # JSON output
            "-P", str(parallel),
        ]

        if protocol.lower() == "udp":
            cmd.append("-u")
            if bandwidth:
                cmd.extend(["-b", bandwidth])

        if reverse:
            cmd.append("-R")

        if bidirectional:
            cmd.append("--bidir")

        if window_size:
            cmd.extend(["-w", window_size])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 30,
            )

            end_time = datetime.now()

            if result.returncode != 0:
                error_msg = result.stderr.strip() or "Unknown error"
                return IperfResult(
                    server=server,
                    port=port,
                    protocol=protocol,
                    duration_sec=duration,
                    direction=self._get_direction(reverse, bidirectional),
                    intervals=[],
                    summary=IperfSummary(
                        bytes_sent=0,
                        bytes_received=0,
                        bits_per_second_sent=0,
                        bits_per_second_received=0,
                        retransmits=None,
                        max_congestion_window=None,
                        min_rtt_ms=None,
                        mean_rtt_ms=None,
                        max_rtt_ms=None,
                    ),
                    start_time=start_time,
                    end_time=end_time,
                    error=error_msg,
                )

            return self._parse_json_output(
                result.stdout,
                server,
                port,
                protocol,
                duration,
                reverse,
                bidirectional,
                start_time,
                end_time,
            )

        except subprocess.TimeoutExpired as e:
            raise ScanError(f"iperf3 test timed out to {server}", str(e)) from e
        except Exception as e:
            raise ScanError(f"iperf3 test failed to {server}", str(e)) from e

    def _get_direction(self, reverse: bool, bidirectional: bool) -> str:
        """Determine test direction."""
        if bidirectional:
            return "bidirectional"
        return "download" if reverse else "upload"

    def _parse_json_output(
        self,
        output: str,
        server: str,
        port: int,
        protocol: str,
        duration: int,
        reverse: bool,
        bidirectional: bool,
        start_time: datetime,
        end_time: datetime,
    ) -> IperfResult:
        """Parse iperf3 JSON output."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            return IperfResult(
                server=server,
                port=port,
                protocol=protocol,
                duration_sec=duration,
                direction=self._get_direction(reverse, bidirectional),
                intervals=[],
                summary=IperfSummary(
                    bytes_sent=0,
                    bytes_received=0,
                    bits_per_second_sent=0,
                    bits_per_second_received=0,
                    retransmits=None,
                    max_congestion_window=None,
                    min_rtt_ms=None,
                    mean_rtt_ms=None,
                    max_rtt_ms=None,
                ),
                start_time=start_time,
                end_time=end_time,
                error=f"Failed to parse output: {e}",
            )

        # Check for error in response
        if "error" in data:
            return IperfResult(
                server=server,
                port=port,
                protocol=protocol,
                duration_sec=duration,
                direction=self._get_direction(reverse, bidirectional),
                intervals=[],
                summary=IperfSummary(
                    bytes_sent=0,
                    bytes_received=0,
                    bits_per_second_sent=0,
                    bits_per_second_received=0,
                    retransmits=None,
                    max_congestion_window=None,
                    min_rtt_ms=None,
                    mean_rtt_ms=None,
                    max_rtt_ms=None,
                ),
                start_time=start_time,
                end_time=end_time,
                error=data["error"],
            )

        # Parse intervals
        intervals = []
        for interval_data in data.get("intervals", []):
            streams = interval_data.get("streams", [])
            if streams:
                stream = streams[0]  # Use first stream for simplicity
                intervals.append(
                    IperfInterval(
                        start_sec=stream.get("start", 0),
                        end_sec=stream.get("end", 0),
                        bytes_transferred=stream.get("bytes", 0),
                        bits_per_second=stream.get("bits_per_second", 0),
                        retransmits=stream.get("retransmits"),
                        congestion_window=stream.get("snd_cwnd"),
                    )
                )

        # Parse summary
        end_data = data.get("end", {})
        sum_sent = end_data.get("sum_sent", {})
        sum_received = end_data.get("sum_received", {})

        # For TCP, we have sender/receiver stats
        # For UDP, structure is slightly different
        if protocol.lower() == "udp":
            sum_data = end_data.get("sum", {})
            summary = IperfSummary(
                bytes_sent=sum_data.get("bytes", 0),
                bytes_received=sum_data.get("bytes", 0),
                bits_per_second_sent=sum_data.get("bits_per_second", 0),
                bits_per_second_received=sum_data.get("bits_per_second", 0),
                retransmits=None,
                max_congestion_window=None,
                min_rtt_ms=None,
                mean_rtt_ms=None,
                max_rtt_ms=None,
            )
        else:
            # Get RTT stats from streams
            streams = end_data.get("streams", [])
            sender_stream = streams[0].get("sender", {}) if streams else {}

            summary = IperfSummary(
                bytes_sent=sum_sent.get("bytes", 0),
                bytes_received=sum_received.get("bytes", 0),
                bits_per_second_sent=sum_sent.get("bits_per_second", 0),
                bits_per_second_received=sum_received.get("bits_per_second", 0),
                retransmits=sum_sent.get("retransmits"),
                max_congestion_window=sender_stream.get("max_snd_cwnd"),
                min_rtt_ms=sender_stream.get("min_rtt"),
                mean_rtt_ms=sender_stream.get("mean_rtt"),
                max_rtt_ms=sender_stream.get("max_rtt"),
            )

        return IperfResult(
            server=server,
            port=port,
            protocol=protocol,
            duration_sec=duration,
            direction=self._get_direction(reverse, bidirectional),
            intervals=intervals,
            summary=summary,
            start_time=start_time,
            end_time=end_time,
            error=None,
        )

    def quick_test(self, server: str) -> IperfResult:
        """Quick 5-second upload test."""
        return self.test(server, duration=5)

    def download_test(self, server: str, duration: int = 10) -> IperfResult:
        """Download speed test."""
        return self.test(server, duration=duration, reverse=True)

    def bidirectional_test(self, server: str, duration: int = 10) -> IperfResult:
        """Bidirectional throughput test."""
        return self.test(server, duration=duration, bidirectional=True)

    def udp_test(
        self,
        server: str,
        bandwidth: str = "100M",
        duration: int = 10,
    ) -> IperfResult:
        """UDP jitter/packet loss test."""
        return self.test(server, protocol="udp", bandwidth=bandwidth, duration=duration)


class IperfServer:
    """Wrapper for running iperf3 server.

    Can be used to set up a local iperf3 server for testing.
    """

    def __init__(self) -> None:
        if not check_dependency("iperf3"):
            raise DependencyError(
                "iperf3",
                "Install with: brew install iperf3 (macOS) or apt install iperf3 (Linux)",
            )

        self._process: subprocess.Popen | None = None

    def start(
        self,
        port: int = 5201,
        one_off: bool = True,
    ) -> bool:
        """
        Start iperf3 server.

        Args:
            port: Port to listen on
            one_off: Exit after single client test

        Returns:
            True if server started successfully
        """
        if self._process is not None:
            return False

        cmd = ["iperf3", "-s", "-p", str(port)]

        if one_off:
            cmd.append("-1")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return True
        except Exception:
            return False

    def stop(self) -> bool:
        """Stop iperf3 server."""
        if self._process is None:
            return False

        try:
            self._process.terminate()
            self._process.wait(timeout=5)
            self._process = None
            return True
        except Exception:
            if self._process:
                self._process.kill()
                self._process = None
            return False

    def is_running(self) -> bool:
        """Check if server is running."""
        if self._process is None:
            return False
        return self._process.poll() is None
