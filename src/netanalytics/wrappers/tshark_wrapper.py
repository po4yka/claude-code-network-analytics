"""Wrapper for tshark/Wireshark using PyShark."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Any
import subprocess

from ..core.exceptions import CaptureError, DependencyError
from ..core.utils import check_dependency


@dataclass
class PacketInfo:
    """Basic packet information."""

    number: int
    timestamp: datetime
    source: str
    destination: str
    protocol: str
    length: int
    info: str

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
        }


@dataclass
class TsharkAnalysis:
    """Analysis results from tshark."""

    packet_count: int
    protocols: dict[str, int]
    conversations: list[dict]
    endpoints: list[dict]
    io_stats: dict

    def to_dict(self) -> dict:
        return {
            "packet_count": self.packet_count,
            "protocols": self.protocols,
            "conversations": self.conversations,
            "endpoints": self.endpoints,
            "io_stats": self.io_stats,
        }


class TsharkCapture:
    """Wrapper for tshark packet capture and analysis."""

    def __init__(self) -> None:
        if not check_dependency("tshark"):
            raise DependencyError(
                "tshark",
                "Install Wireshark: brew install wireshark (macOS) or apt install tshark (Linux)",
            )

    def capture(
        self,
        interface: str,
        count: int = 100,
        timeout: int = 60,
        display_filter: str | None = None,
        output_file: str | None = None,
    ) -> list[PacketInfo]:
        """
        Capture packets using tshark.

        Args:
            interface: Network interface to capture on
            count: Maximum number of packets
            timeout: Capture timeout in seconds
            display_filter: Wireshark display filter
            output_file: Output pcap file path

        Returns:
            List of captured packet info
        """
        try:
            import pyshark
        except ImportError:
            raise DependencyError("pyshark", "Install with: pip install pyshark")

        capture_args = {
            "interface": interface,
            "only_summaries": True,
        }

        if display_filter:
            capture_args["display_filter"] = display_filter

        if output_file:
            capture_args["output_file"] = output_file

        try:
            capture = pyshark.LiveCapture(**capture_args)
            packets = []

            for i, packet in enumerate(capture.sniff_continuously(packet_count=count)):
                if i >= count:
                    break

                try:
                    info = PacketInfo(
                        number=i + 1,
                        timestamp=datetime.fromtimestamp(float(packet.sniff_timestamp)),
                        source=getattr(packet, "source", "unknown"),
                        destination=getattr(packet, "destination", "unknown"),
                        protocol=packet.highest_layer,
                        length=int(packet.length),
                        info=str(packet.info) if hasattr(packet, "info") else "",
                    )
                    packets.append(info)
                except Exception:
                    continue

            capture.close()
            return packets

        except Exception as e:
            raise CaptureError(f"Tshark capture failed on {interface}", str(e))

    def read_pcap(self, pcap_file: str) -> list[PacketInfo]:
        """
        Read packets from a pcap file.

        Args:
            pcap_file: Path to pcap file

        Returns:
            List of packet info
        """
        try:
            import pyshark
        except ImportError:
            raise DependencyError("pyshark", "Install with: pip install pyshark")

        if not Path(pcap_file).exists():
            raise CaptureError(f"Pcap file not found: {pcap_file}")

        try:
            capture = pyshark.FileCapture(pcap_file, only_summaries=True)
            packets = []

            for i, packet in enumerate(capture):
                try:
                    info = PacketInfo(
                        number=i + 1,
                        timestamp=datetime.fromtimestamp(float(packet.sniff_timestamp)),
                        source=getattr(packet, "source", "unknown"),
                        destination=getattr(packet, "destination", "unknown"),
                        protocol=packet.highest_layer,
                        length=int(packet.length),
                        info=str(packet.info) if hasattr(packet, "info") else "",
                    )
                    packets.append(info)
                except Exception:
                    continue

            capture.close()
            return packets

        except Exception as e:
            raise CaptureError(f"Failed to read pcap file: {pcap_file}", str(e))

    def analyze(self, pcap_file: str) -> TsharkAnalysis:
        """
        Analyze a pcap file using tshark statistics.

        Args:
            pcap_file: Path to pcap file

        Returns:
            TsharkAnalysis with statistics
        """
        if not Path(pcap_file).exists():
            raise CaptureError(f"Pcap file not found: {pcap_file}")

        # Get protocol hierarchy
        protocols = self._run_tshark_stat(pcap_file, "-z", "io,phs")

        # Get conversations
        conversations = self._run_tshark_stat(pcap_file, "-z", "conv,ip")

        # Get endpoints
        endpoints = self._run_tshark_stat(pcap_file, "-z", "endpoints,ip")

        # Count packets
        packet_count = self._count_packets(pcap_file)

        return TsharkAnalysis(
            packet_count=packet_count,
            protocols=protocols,
            conversations=conversations,
            endpoints=endpoints,
            io_stats={},
        )

    def _run_tshark_stat(self, pcap_file: str, *args: str) -> Any:
        """Run tshark with statistics options."""
        cmd = ["tshark", "-r", pcap_file, "-q"] + list(args)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                return {}
            return self._parse_stat_output(result.stdout)
        except subprocess.TimeoutExpired:
            return {}
        except Exception:
            return {}

    def _parse_stat_output(self, output: str) -> dict:
        """Parse tshark statistics output."""
        # Basic parsing - returns raw lines for now
        lines = [line.strip() for line in output.split("\n") if line.strip()]
        return {"raw": lines}

    def _count_packets(self, pcap_file: str) -> int:
        """Count packets in a pcap file."""
        cmd = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.number"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                return 0
            return len(result.stdout.strip().split("\n"))
        except Exception:
            return 0

    def extract_field(self, pcap_file: str, field: str) -> list[str]:
        """
        Extract specific field values from pcap.

        Args:
            pcap_file: Path to pcap file
            field: Wireshark field name (e.g., "ip.src", "http.host")

        Returns:
            List of field values
        """
        cmd = ["tshark", "-r", pcap_file, "-T", "fields", "-e", field]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                return []
            return [v.strip() for v in result.stdout.strip().split("\n") if v.strip()]
        except Exception:
            return []

    def filter_pcap(
        self,
        input_file: str,
        output_file: str,
        display_filter: str,
    ) -> bool:
        """
        Filter pcap file and save to new file.

        Args:
            input_file: Input pcap file
            output_file: Output pcap file
            display_filter: Wireshark display filter

        Returns:
            True if successful
        """
        cmd = ["tshark", "-r", input_file, "-w", output_file, "-Y", display_filter]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.returncode == 0
        except Exception:
            return False
