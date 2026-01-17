"""Wrapper for path tracing tools (mtr)."""

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime

from ..core.exceptions import DependencyError, ScanError
from ..core.utils import check_dependency


@dataclass
class PathHop:
    """Single hop in a path trace."""

    hop_number: int
    host: str | None
    ip: str | None
    loss_percent: float
    sent: int
    received: int
    best_ms: float | None
    avg_ms: float | None
    worst_ms: float | None
    stdev_ms: float | None

    def to_dict(self) -> dict:
        return {
            "hop": self.hop_number,
            "host": self.host,
            "ip": self.ip,
            "loss_percent": self.loss_percent,
            "sent": self.sent,
            "received": self.received,
            "best_ms": self.best_ms,
            "avg_ms": self.avg_ms,
            "worst_ms": self.worst_ms,
            "stdev_ms": self.stdev_ms,
        }


@dataclass
class PathTraceResult:
    """Complete path trace result."""

    target: str
    hops: list[PathHop]
    start_time: datetime
    end_time: datetime
    packet_count: int

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "hops": [h.to_dict() for h in self.hops],
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "packet_count": self.packet_count,
            "hop_count": len(self.hops),
        }


class MtrAnalyzer:
    """Wrapper for mtr (My TraceRoute) network path analyzer.

    mtr combines traceroute and ping functionality to provide
    continuous network path statistics including latency and packet loss.
    """

    def __init__(self) -> None:
        if not check_dependency("mtr"):
            raise DependencyError(
                "mtr",
                "Install with: brew install mtr (macOS) or apt install mtr (Linux)",
            )

    def trace(
        self,
        target: str,
        count: int = 10,
        timeout: int = 60,
        resolve_dns: bool = True,
        ipv4_only: bool = False,
        ipv6_only: bool = False,
    ) -> PathTraceResult:
        """
        Run mtr trace to target.

        Args:
            target: Hostname or IP address to trace
            count: Number of pings per hop (default: 10)
            timeout: Command timeout in seconds
            resolve_dns: Resolve hostnames (default: True)
            ipv4_only: Force IPv4 only
            ipv6_only: Force IPv6 only

        Returns:
            PathTraceResult with hop-by-hop statistics
        """
        start_time = datetime.now()

        # Build mtr command with JSON output
        cmd = ["mtr", "--report", "--json", "-c", str(count)]

        if not resolve_dns:
            cmd.append("--no-dns")

        if ipv4_only:
            cmd.append("-4")
        elif ipv6_only:
            cmd.append("-6")

        cmd.append(target)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                # mtr might not support JSON on all systems, fall back to raw
                return self._trace_raw(target, count, timeout, resolve_dns, start_time)

            hops = self._parse_json_output(result.stdout)
            end_time = datetime.now()

            return PathTraceResult(
                target=target,
                hops=hops,
                start_time=start_time,
                end_time=end_time,
                packet_count=count,
            )

        except subprocess.TimeoutExpired as e:
            raise ScanError(f"mtr trace timed out for {target}", str(e)) from e
        except json.JSONDecodeError:
            # Fall back to raw parsing
            return self._trace_raw(target, count, timeout, resolve_dns, start_time)
        except Exception as e:
            raise ScanError(f"mtr trace failed for {target}", str(e)) from e

    def _trace_raw(
        self,
        target: str,
        count: int,
        timeout: int,
        resolve_dns: bool,
        start_time: datetime,
    ) -> PathTraceResult:
        """Fall back to raw text parsing for mtr without JSON support."""
        cmd = ["mtr", "--report", "-c", str(count)]

        if not resolve_dns:
            cmd.append("--no-dns")

        cmd.append(target)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            hops = self._parse_raw_output(result.stdout)
            end_time = datetime.now()

            return PathTraceResult(
                target=target,
                hops=hops,
                start_time=start_time,
                end_time=end_time,
                packet_count=count,
            )

        except subprocess.TimeoutExpired as e:
            raise ScanError(f"mtr trace timed out for {target}", str(e)) from e
        except Exception as e:
            raise ScanError(f"mtr trace failed for {target}", str(e)) from e

    def _parse_json_output(self, output: str) -> list[PathHop]:
        """Parse mtr JSON output."""
        data = json.loads(output)
        hops = []

        report = data.get("report", {})
        hub_list = report.get("hubs", [])

        for hub in hub_list:
            hop = PathHop(
                hop_number=hub.get("count", 0),
                host=hub.get("host") if hub.get("host") != "???" else None,
                ip=hub.get("host") if self._is_ip(hub.get("host", "")) else None,
                loss_percent=hub.get("Loss%", 0.0),
                sent=hub.get("Snt", 0),
                received=hub.get("Snt", 0) - int(hub.get("Loss%", 0) * hub.get("Snt", 0) / 100),
                best_ms=hub.get("Best") if hub.get("Best") else None,
                avg_ms=hub.get("Avg") if hub.get("Avg") else None,
                worst_ms=hub.get("Wrst") if hub.get("Wrst") else None,
                stdev_ms=hub.get("StDev") if hub.get("StDev") else None,
            )
            hops.append(hop)

        return hops

    def _parse_raw_output(self, output: str) -> list[PathHop]:
        """Parse mtr raw text output."""
        hops = []
        lines = output.strip().split("\n")

        # Skip header lines (Start, HOST, etc.)
        data_started = False

        for line in lines:
            line = line.strip()

            # Skip empty lines and headers
            if not line or line.startswith("Start:") or line.startswith("HOST:"):
                data_started = True
                continue

            if not data_started:
                continue

            # Parse hop line: "1.|-- host  0.0%  10  0.5  0.6  0.5  1.0  0.1"
            # or "1. host  0.0%  10  0.5  0.6  0.5  1.0  0.1"
            match = re.match(
                r"^\s*(\d+)[\.\|]+[-\s]*([^\s]+)\s+"
                r"([\d.]+)%?\s+"
                r"(\d+)\s+"
                r"([\d.]+)\s+"
                r"([\d.]+)\s+"
                r"([\d.]+)\s+"
                r"([\d.]+)(?:\s+([\d.]+))?",
                line,
            )

            if match:
                host = match.group(2)
                is_unknown = host in ("???", "")

                hop = PathHop(
                    hop_number=int(match.group(1)),
                    host=None if is_unknown else host,
                    ip=host if self._is_ip(host) else None,
                    loss_percent=float(match.group(3)),
                    sent=int(match.group(4)),
                    received=int(int(match.group(4)) * (1 - float(match.group(3)) / 100)),
                    best_ms=float(match.group(5)) if match.group(5) else None,
                    avg_ms=float(match.group(6)) if match.group(6) else None,
                    worst_ms=float(match.group(7)) if match.group(7) else None,
                    stdev_ms=float(match.group(8)) if match.group(8) else None,
                )
                hops.append(hop)

        return hops

    def _is_ip(self, s: str) -> bool:
        """Check if string looks like an IP address."""
        if not s or s == "???":
            return False
        # Simple check for IPv4 or IPv6
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s)) or ":" in s

    def quick_trace(self, target: str) -> PathTraceResult:
        """Quick trace with fewer probes."""
        return self.trace(target, count=3)

    def detailed_trace(self, target: str) -> PathTraceResult:
        """Detailed trace with more probes for accurate statistics."""
        return self.trace(target, count=20)
