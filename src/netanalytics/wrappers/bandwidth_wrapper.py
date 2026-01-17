"""Wrapper for bandwidth monitoring tools (bandwhich, vnstat)."""

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime

from ..core.exceptions import CaptureError, DependencyError
from ..core.utils import check_dependency, is_root


@dataclass
class ProcessBandwidth:
    """Bandwidth usage for a single process."""

    process_name: str
    pid: int | None
    upload_bytes_sec: int
    download_bytes_sec: int
    connections: int

    def to_dict(self) -> dict:
        return {
            "process_name": self.process_name,
            "pid": self.pid,
            "upload_bytes_sec": self.upload_bytes_sec,
            "download_bytes_sec": self.download_bytes_sec,
            "upload_human": self._humanize(self.upload_bytes_sec),
            "download_human": self._humanize(self.download_bytes_sec),
            "connections": self.connections,
        }

    def _humanize(self, bytes_sec: int) -> str:
        """Convert bytes/s to human readable format."""
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if bytes_sec < 1024:
                return f"{bytes_sec:.1f} {unit}"
            bytes_sec = bytes_sec // 1024
        return f"{bytes_sec:.1f} TB/s"


@dataclass
class ConnectionBandwidth:
    """Bandwidth usage for a single connection."""

    local_addr: str
    remote_addr: str
    protocol: str
    upload_bytes_sec: int
    download_bytes_sec: int
    process_name: str | None

    def to_dict(self) -> dict:
        return {
            "local_addr": self.local_addr,
            "remote_addr": self.remote_addr,
            "protocol": self.protocol,
            "upload_bytes_sec": self.upload_bytes_sec,
            "download_bytes_sec": self.download_bytes_sec,
            "process_name": self.process_name,
        }


@dataclass
class BandwhichResult:
    """bandwhich monitoring result."""

    processes: list[ProcessBandwidth]
    connections: list[ConnectionBandwidth]
    total_upload_bytes_sec: int
    total_download_bytes_sec: int
    capture_time: datetime
    duration_seconds: int

    def to_dict(self) -> dict:
        return {
            "processes": [p.to_dict() for p in self.processes],
            "connections": [c.to_dict() for c in self.connections[:50]],  # Limit
            "total_upload_bytes_sec": self.total_upload_bytes_sec,
            "total_download_bytes_sec": self.total_download_bytes_sec,
            "capture_time": self.capture_time.isoformat(),
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class VnstatInterface:
    """Traffic statistics for a network interface."""

    interface: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    period: str

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "rx_human": self._humanize(self.rx_bytes),
            "tx_human": self._humanize(self.tx_bytes),
            "rx_packets": self.rx_packets,
            "tx_packets": self.tx_packets,
            "period": self.period,
        }

    def _humanize(self, bytes_val: int) -> str:
        """Convert bytes to human readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val = bytes_val // 1024
        return f"{bytes_val:.2f} PB"


@dataclass
class VnstatResult:
    """vnstat traffic statistics result."""

    interfaces: list[VnstatInterface]
    query_time: datetime
    period: str  # "hourly", "daily", "monthly", "total"

    def to_dict(self) -> dict:
        return {
            "interfaces": [i.to_dict() for i in self.interfaces],
            "query_time": self.query_time.isoformat(),
            "period": self.period,
        }


class BandwhichMonitor:
    """Wrapper for bandwhich bandwidth monitor.

    bandwhich shows bandwidth utilization by process, connection, and
    remote IP/hostname. Requires root privileges.
    """

    def __init__(self) -> None:
        if not check_dependency("bandwhich"):
            raise DependencyError(
                "bandwhich",
                "Install with: brew install bandwhich (macOS) or cargo install bandwhich (Linux)",
            )

    def snapshot(
        self,
        duration: int = 5,
        interface: str | None = None,
    ) -> BandwhichResult:
        """
        Take a bandwidth snapshot over a duration.

        Args:
            duration: Monitoring duration in seconds (default: 5)
            interface: Specific interface to monitor (optional)

        Returns:
            BandwhichResult with process and connection bandwidth
        """
        if not is_root():
            raise CaptureError("bandwhich requires root privileges")

        capture_time = datetime.now()

        cmd = ["bandwhich", "--raw", "-t", str(duration)]

        if interface:
            cmd.extend(["-i", interface])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 10,
            )

            processes, connections = self._parse_raw_output(result.stdout)

            total_up = sum(p.upload_bytes_sec for p in processes)
            total_down = sum(p.download_bytes_sec for p in processes)

            return BandwhichResult(
                processes=processes,
                connections=connections,
                total_upload_bytes_sec=total_up,
                total_download_bytes_sec=total_down,
                capture_time=capture_time,
                duration_seconds=duration,
            )

        except subprocess.TimeoutExpired as e:
            raise CaptureError(f"bandwhich timed out after {duration}s", str(e)) from e
        except Exception as e:
            raise CaptureError("bandwhich monitoring failed", str(e)) from e

    def _parse_raw_output(
        self, output: str
    ) -> tuple[list[ProcessBandwidth], list[ConnectionBandwidth]]:
        """Parse bandwhich raw output."""
        processes = []
        connections = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            # Try to parse as process line
            proc = self._parse_process_line(line)
            if proc:
                processes.append(proc)
                continue

            # Try to parse as connection line
            conn = self._parse_connection_line(line)
            if conn:
                connections.append(conn)

        return processes, connections

    def _parse_process_line(self, line: str) -> ProcessBandwidth | None:
        """Parse a process bandwidth line."""
        # Format varies, try common patterns
        match = re.match(
            r"^(\S+)\s+(?:pid:\s*(\d+))?\s*"
            r"up:\s*([\d.]+)\s*(\w+)/s\s+"
            r"down:\s*([\d.]+)\s*(\w+)/s\s*"
            r"(?:conns?:\s*(\d+))?",
            line,
            re.IGNORECASE,
        )

        if match:
            return ProcessBandwidth(
                process_name=match.group(1),
                pid=int(match.group(2)) if match.group(2) else None,
                upload_bytes_sec=self._parse_rate(match.group(3), match.group(4)),
                download_bytes_sec=self._parse_rate(match.group(5), match.group(6)),
                connections=int(match.group(7)) if match.group(7) else 0,
            )

        return None

    def _parse_connection_line(self, line: str) -> ConnectionBandwidth | None:
        """Parse a connection bandwidth line."""
        # Format: local:port -> remote:port proto up:X down:Y [process]
        match = re.match(
            r"^(\S+:\d+)\s*->\s*(\S+:\d+)\s+(\w+)\s+"
            r"up:\s*([\d.]+)\s*(\w+)/s\s+"
            r"down:\s*([\d.]+)\s*(\w+)/s\s*"
            r"(?:\[(\S+)\])?",
            line,
            re.IGNORECASE,
        )

        if match:
            return ConnectionBandwidth(
                local_addr=match.group(1),
                remote_addr=match.group(2),
                protocol=match.group(3).upper(),
                upload_bytes_sec=self._parse_rate(match.group(4), match.group(5)),
                download_bytes_sec=self._parse_rate(match.group(6), match.group(7)),
                process_name=match.group(8),
            )

        return None

    def _parse_rate(self, value: str, unit: str) -> int:
        """Parse rate value with unit to bytes/sec."""
        val = float(value)
        unit = unit.upper()

        multipliers = {
            "B": 1,
            "KB": 1024,
            "MB": 1024 * 1024,
            "GB": 1024 * 1024 * 1024,
            "K": 1024,
            "M": 1024 * 1024,
            "G": 1024 * 1024 * 1024,
        }

        return int(val * multipliers.get(unit, 1))


class VnstatMonitor:
    """Wrapper for vnstat traffic statistics.

    vnstat is a console-based network traffic monitor that keeps a log
    of hourly, daily, and monthly network traffic. It uses kernel
    statistics so it's lightweight.
    """

    def __init__(self) -> None:
        if not check_dependency("vnstat"):
            raise DependencyError(
                "vnstat",
                "Install with: brew install vnstat (macOS) or apt install vnstat (Linux)",
            )

    def get_stats(
        self,
        interface: str | None = None,
        period: str = "daily",
    ) -> VnstatResult:
        """
        Get traffic statistics.

        Args:
            interface: Specific interface (default: all)
            period: Period type - "hourly", "daily", "monthly", "total"

        Returns:
            VnstatResult with traffic statistics
        """
        query_time = datetime.now()

        cmd = ["vnstat", "--json"]

        if interface:
            cmd.extend(["-i", interface])

        # Add period flag
        period_flags = {
            "hourly": "-h",
            "daily": "-d",
            "monthly": "-m",
            "total": "--oneline",
        }

        if period in period_flags and period != "total":
            cmd.append(period_flags[period])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                # vnstat might not have data yet
                if "no data available" in result.stderr.lower():
                    return VnstatResult(
                        interfaces=[],
                        query_time=query_time,
                        period=period,
                    )
                raise CaptureError(f"vnstat failed: {result.stderr}")

            interfaces = self._parse_json_output(result.stdout, period)

            return VnstatResult(
                interfaces=interfaces,
                query_time=query_time,
                period=period,
            )

        except json.JSONDecodeError:
            # Fall back to text parsing
            return self._parse_text_output(interface, period, query_time)
        except Exception as e:
            raise CaptureError("vnstat query failed", str(e)) from e

    def _parse_json_output(self, output: str, period: str) -> list[VnstatInterface]:
        """Parse vnstat JSON output."""
        data = json.loads(output)
        interfaces = []

        for iface in data.get("interfaces", []):
            name = iface.get("name", "unknown")
            traffic = iface.get("traffic", {})

            # Get appropriate period data
            if period == "total":
                totals = traffic.get("total", {})
                rx = totals.get("rx", 0)
                tx = totals.get("tx", 0)
            elif period == "daily":
                days = traffic.get("day", [])
                rx = sum(d.get("rx", 0) for d in days[-1:])  # Last day
                tx = sum(d.get("tx", 0) for d in days[-1:])
            elif period == "monthly":
                months = traffic.get("month", [])
                rx = sum(m.get("rx", 0) for m in months[-1:])  # Last month
                tx = sum(m.get("tx", 0) for m in months[-1:])
            elif period == "hourly":
                hours = traffic.get("hour", [])
                rx = sum(h.get("rx", 0) for h in hours[-1:])  # Last hour
                tx = sum(h.get("tx", 0) for h in hours[-1:])
            else:
                rx = tx = 0

            interfaces.append(
                VnstatInterface(
                    interface=name,
                    rx_bytes=rx,
                    tx_bytes=tx,
                    rx_packets=0,  # Not always in JSON
                    tx_packets=0,
                    period=period,
                )
            )

        return interfaces

    def _parse_text_output(
        self,
        interface: str | None,
        period: str,
        query_time: datetime,
    ) -> VnstatResult:
        """Fall back to text output parsing."""
        cmd = ["vnstat"]

        if interface:
            cmd.extend(["-i", interface])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            interfaces = []
            current_iface = None

            for line in result.stdout.split("\n"):
                # Interface header
                if line.strip() and not line.startswith(" "):
                    iface_match = re.match(r"^(\S+):", line)
                    if iface_match:
                        current_iface = iface_match.group(1)

                # Total line: "total:     X.XX GiB /   Y.YY GiB"
                if current_iface and "total:" in line.lower():
                    match = re.search(
                        r"total:\s*([\d.]+)\s*(\w+)\s*/\s*([\d.]+)\s*(\w+)",
                        line,
                        re.IGNORECASE,
                    )
                    if match:
                        rx = self._parse_size(match.group(1), match.group(2))
                        tx = self._parse_size(match.group(3), match.group(4))

                        interfaces.append(
                            VnstatInterface(
                                interface=current_iface,
                                rx_bytes=rx,
                                tx_bytes=tx,
                                rx_packets=0,
                                tx_packets=0,
                                period=period,
                            )
                        )

            return VnstatResult(
                interfaces=interfaces,
                query_time=query_time,
                period=period,
            )

        except Exception:
            return VnstatResult(
                interfaces=[],
                query_time=query_time,
                period=period,
            )

    def _parse_size(self, value: str, unit: str) -> int:
        """Parse size value with unit to bytes."""
        val = float(value)
        unit = unit.upper()

        multipliers = {
            "B": 1,
            "KIB": 1024,
            "MIB": 1024 * 1024,
            "GIB": 1024 * 1024 * 1024,
            "TIB": 1024 * 1024 * 1024 * 1024,
            "KB": 1000,
            "MB": 1000 * 1000,
            "GB": 1000 * 1000 * 1000,
            "TB": 1000 * 1000 * 1000 * 1000,
        }

        return int(val * multipliers.get(unit, 1))

    def is_daemon_running(self) -> bool:
        """Check if vnstatd daemon is running."""
        try:
            result = subprocess.run(
                ["pgrep", "-x", "vnstatd"],
                capture_output=True,
            )
            return result.returncode == 0
        except Exception:
            return False

    def start_daemon(self) -> bool:
        """Start vnstatd daemon (requires root)."""
        if not is_root():
            raise CaptureError("Starting vnstatd requires root privileges")

        try:
            subprocess.run(
                ["vnstatd", "-d"],
                capture_output=True,
                timeout=10,
            )
            return self.is_daemon_running()
        except Exception:
            return False

    def update_database(self, interface: str | None = None) -> bool:
        """Force database update for interface."""
        cmd = ["vnstat", "--update"]

        if interface:
            cmd.extend(["-i", interface])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30,
            )
            return result.returncode == 0
        except Exception:
            return False

    def list_interfaces(self) -> list[str]:
        """List interfaces tracked by vnstat."""
        try:
            result = subprocess.run(
                ["vnstat", "--iflist"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                # Parse output: "Available interfaces: eth0 wlan0 lo"
                match = re.search(r"Available interfaces:\s*(.+)", result.stdout)
                if match:
                    return match.group(1).strip().split()

            return []
        except Exception:
            return []
